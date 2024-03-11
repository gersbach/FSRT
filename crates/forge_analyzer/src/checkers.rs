use core::fmt;
use forge_permission_resolver::permissions_resolver::{check_url_for_permissions, RequestType};
use forge_utils::FxHashMap;
use itertools::Itertools;
use smallvec::SmallVec;
use std::{
    cmp::max,
    iter::{self, zip},
    mem,
    ops::ControlFlow,
    path::PathBuf,
};

use tracing::{debug, info, warn};

use crate::interp::ProjectionVec;
use crate::utils::projvec_from_str;
use crate::{
    definitions::{Const, DefId, Environment, IntrinsicName, Value},
    interp::{
        Checker, Dataflow, EntryKind, EntryPoint, Frame, Interp, JoinSemiLattice, Runner,
        WithCallStack,
    },
    ir::{
        Base, BasicBlock, BasicBlockId, BinOp, Inst, Intrinsic, Literal, Location, Operand,
        Projection, Rvalue, VarId, VarKind, Variable,
    },
    reporter::{IntoVuln, Reporter, Severity, Vulnerability},
    utils::{
        add_const_to_val_vec, add_elements_to_intrinsic_struct, convert_operand_to_raw,
        get_defid_from_varkind, get_prev_value, get_str_from_operand, return_value_from_string,
        translate_request_type,
    },
    worklist::WorkList,
};

#[derive(Debug, PartialEq, Eq, Clone, Copy, PartialOrd, Ord, Default)]
pub enum Taint {
    No,
    Yes,
    #[default]
    Unknown,
}

impl JoinSemiLattice for Taint {
    const BOTTOM: Self = Self::No;

    #[inline]
    fn join_changed(&mut self, other: &Self) -> bool {
        let old = mem::replace(self, max(*other, *self));
        old == *self
    }

    #[inline]
    fn join(&self, other: &Self) -> Self {
        max(*other, *self)
    }
}

impl<D: JoinSemiLattice> JoinSemiLattice for Vec<D> {
    const BOTTOM: Self = vec![];
    fn join_changed(&mut self, other: &Self) -> bool {
        let mut changed = false;
        for (l, r) in zip(self, other) {
            changed |= l.join_changed(r);
        }
        changed
    }
    fn join(&self, other: &Self) -> Self {
        self.iter()
            .zip(other.iter())
            .map(|(a, b)| a.join(b))
            .collect()
    }
}

pub struct TaintDataflow {
    started: bool,
}

impl<'cx> Dataflow<'cx> for TaintDataflow {
    type State = Vec<Taint>;

    fn with_interp<C: Runner<'cx, State = Self::State>>(_interp: &Interp<'cx, C>) -> Self {
        Self { started: false }
    }

    fn transfer_call<C: Runner<'cx, State = Self::State>>(
        &mut self,
        _interp: &Interp<'cx, C>,
        _def: DefId,
        _loc: Location,
        _block: &'cx BasicBlock,
        _callee: &'cx Operand,
        initial_state: Self::State,
        _oprands: SmallVec<[crate::ir::Operand; 4]>,
    ) -> Self::State {
        initial_state
    }

    fn transfer_intrinsic<C: Runner<'cx, State = Self::State>>(
        &mut self,
        _interp: &mut Interp<'cx, C>,
        _def: DefId,
        _loc: Location,
        _block: &'cx BasicBlock,
        _intrinsic: &'cx Intrinsic,
        initial_state: Self::State,
        _operands: SmallVec<[crate::ir::Operand; 4]>,
    ) -> Self::State {
        initial_state
    }

    fn transfer_inst<C: Runner<'cx, State = Self::State>>(
        &mut self,
        interp: &mut Interp<'cx, C>,
        def: DefId,
        loc: Location,
        block: &'cx BasicBlock,
        inst: &'cx Inst,
        mut initial_state: Self::State,
    ) -> Self::State {
        match inst {
            Inst::Assign(l, v) => {
                let Some(var) = l.as_var_id() else {
                    return initial_state;
                };

                if let Some(var) = v.as_var() {
                    let Some(var_id) = var.as_var_id() else {
                        return initial_state;
                    };
                    let taint = initial_state[var_id.0 as usize];
                    if !self.started && taint == Taint::Yes {
                        let Some(Projection::Known(s)) = var.projections.first() else {
                            return initial_state;
                        };
                        if *s == "payload" {
                            initial_state[var_id.0 as usize] = Taint::Yes;
                            self.started = true;
                        }
                        return initial_state;
                    } else {
                        let new_state = initial_state[var_id.0 as usize].join(&taint);
                        initial_state[var_id.0 as usize] = new_state;
                        return initial_state;
                    }
                } else if initial_state[var.0 as usize] == Taint::Yes {
                    initial_state[var.0 as usize] = Taint::Unknown;
                }
                initial_state
            }
            Inst::Expr(rvalue) => {
                self.transfer_rvalue(interp, def, loc, block, rvalue, initial_state)
            }
        }
    }

    fn transfer_block<C: Runner<'cx, State = Self::State>>(
        &mut self,
        interp: &mut Interp<'cx, C>,
        def: DefId,
        bb: BasicBlockId,
        block: &'cx BasicBlock,
        mut initial_state: Self::State,
        _arguments: Option<Vec<Value>>,
    ) -> Self::State {
        if initial_state.len() < interp.body().vars.len() {
            initial_state.resize(interp.body().vars.len(), Taint::Unknown);
        }
        if matches!(interp.entry.kind, EntryKind::Resolver(..)) {
            debug!("analyzing resolver");
            let kind = interp.body().vars.get(VarId::from(1));
            if matches!(kind, Some(VarKind::Arg(_))) {
                debug!("found taint start");
                initial_state[1] = Taint::Yes;
            } else {
                debug!(first_var = ?kind, "no arguments read");
            }
        }
        for (idx, inst) in block.iter().enumerate() {
            initial_state = self.transfer_inst(
                interp,
                def,
                Location::new(bb, idx as u32),
                block,
                inst,
                initial_state,
            );
        }
        initial_state
    }
}

pub struct AuthorizeDataflow {
    needs_call: Vec<DefId>,
}

#[derive(Debug, PartialEq, Eq, Clone, Copy, PartialOrd, Ord)]
pub enum AuthorizeState {
    No,
    CustomFieldOnly,
    Yes,
}

impl JoinSemiLattice for AuthorizeState {
    const BOTTOM: Self = Self::No;

    #[inline]
    fn join_changed(&mut self, other: &Self) -> bool {
        let old = mem::replace(self, max(*other, *self));
        old == *self
    }

    #[inline]
    fn join(&self, other: &Self) -> Self {
        max(*other, *self)
    }
}

impl<'cx> Dataflow<'cx> for AuthorizeDataflow {
    type State = AuthorizeState;

    fn with_interp<C: crate::interp::Runner<'cx, State = Self::State>>(
        _interp: &Interp<'cx, C>,
    ) -> Self {
        Self { needs_call: vec![] }
    }

    fn transfer_intrinsic<C: crate::interp::Runner<'cx, State = Self::State>>(
        &mut self,
        _interp: &mut Interp<'cx, C>,
        _def: DefId,
        _loc: Location,
        _block: &'cx BasicBlock,
        intrinsic: &'cx Intrinsic,
        initial_state: Self::State,
        _operands: SmallVec<[crate::ir::Operand; 4]>,
    ) -> Self::State {
        match *intrinsic {
            Intrinsic::Authorize(_) => {
                debug!("authorize intrinsic found");
                AuthorizeState::Yes
            }
            Intrinsic::UserFieldAccess => {
                debug!("user field access found");
                std::cmp::max(AuthorizeState::CustomFieldOnly, initial_state)
            }
            Intrinsic::SecretFunction(_)
            | Intrinsic::Fetch
            | Intrinsic::ApiCustomField
            | Intrinsic::ApiCall(_)
            | Intrinsic::SafeCall(_)
            | Intrinsic::EnvRead
            | Intrinsic::StorageRead => initial_state,
        }
    }

    fn transfer_call<C: crate::interp::Runner<'cx, State = Self::State>>(
        &mut self,
        interp: &Interp<'cx, C>,
        def: DefId,
        loc: Location,
        _block: &'cx BasicBlock,
        callee: &'cx crate::ir::Operand,
        initial_state: Self::State,
        _operands: SmallVec<[crate::ir::Operand; 4]>,
    ) -> Self::State {
        let Some((callee_def, _body)) = self.resolve_call(interp, callee) else {
            return initial_state;
        };
        match interp.func_state(callee_def) {
            Some(state) => {
                if state == AuthorizeState::Yes {
                    debug!("Found call to authorize at {def:?} {loc:?}");
                }
                initial_state.join(&state)
            }
            None => {
                let callee_name = interp.env().def_name(callee_def);
                let caller_name = interp.env().def_name(def);
                debug!("Found call to {callee_name} at {def:?} {caller_name}");
                self.needs_call.push(callee_def);
                initial_state
            }
        }
    }

    fn join_term<C: crate::interp::Runner<'cx, State = Self::State>>(
        &mut self,
        interp: &mut Interp<'cx, C>,
        def: DefId,
        block: &'cx BasicBlock,
        state: Self::State,
        worklist: &mut WorkList<DefId, BasicBlockId>,
    ) {
        self.super_join_term(interp, def, block, state, worklist);
        for def in self.needs_call.drain(..) {
            worklist.push_front_blocks(interp.env(), def, interp.call_all);
        }
    }
}

pub struct PrototypePollutionChecker;

#[derive(Debug, Clone, Copy, PartialOrd, Ord, PartialEq, Eq, Default)]
enum PrototypePollutionState {
    Yes,
    #[default]
    No,
}

impl JoinSemiLattice for PrototypePollutionState {
    const BOTTOM: Self = Self::No;
    fn join(&self, other: &Self) -> Self {
        match (self, other) {
            (Self::Yes, _) | (_, Self::Yes) => Self::Yes,
            _ => Self::No,
        }
    }

    fn join_changed(&mut self, other: &Self) -> bool {
        let old = mem::replace(self, self.join(other));
        old != *self
    }
}

impl<'cx> Runner<'cx> for PrototypePollutionChecker {
    type State = Vec<Taint>;

    type Dataflow = TaintDataflow;

    const NAME: &'static str = "PrototypePollution";

    fn visit_intrinsic(
        &mut self,
        _interp: &Interp<'cx, Self>,
        _intrinsic: &'cx Intrinsic,
        _def: DefId,
        state: &Self::State,
        _operands: Option<SmallVec<[Operand; 4]>>,
    ) -> ControlFlow<(), Self::State> {
        ControlFlow::Continue(state.clone())
    }
    fn visit_block(
        &mut self,
        _interp: &Interp<'cx, Self>,
        _def: DefId,
        _id: BasicBlockId,
        block: &'cx BasicBlock,
        curr_state: &Self::State,
    ) -> ControlFlow<(), Self::State> {
        for inst in &block.insts {
            if let Inst::Assign(l, _r) = inst {
                if let [Projection::Computed(Base::Var(fst)), Projection::Computed(Base::Var(snd)), ..] =
                    *l.projections
                {
                    if curr_state.get(fst.0 as usize).copied() == Some(Taint::Yes)
                        && curr_state.get(snd.0 as usize).copied() == Some(Taint::Yes)
                    {
                        info!("Prototype pollution vuln detected");
                        return ControlFlow::Break(());
                    }
                }
            }
        }
        ControlFlow::Continue(curr_state.clone())
    }
}

pub struct AuthZChecker {
    vulns: Vec<AuthZVuln>,
}

impl AuthZChecker {
    pub fn new() -> Self {
        Self { vulns: vec![] }
    }

    pub fn into_vulns(self) -> impl IntoIterator<Item = AuthZVuln> {
        // TODO: make this an associated function on the Checker trait.
        self.vulns.into_iter()
    }
}

impl Default for AuthZChecker {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug)]
pub struct AuthZVuln {
    stack: String,
    entry_func: String,
    file: PathBuf,
}

impl AuthZVuln {
    fn new(callstack: Vec<Frame>, env: &Environment, entry: &EntryPoint) -> Self {
        let entry_func = match &entry.kind {
            EntryKind::Function(func) => func.clone(),
            EntryKind::Resolver(res, prop) => format!("{res}.{prop}"),
            EntryKind::Empty => {
                warn!("empty function");
                String::new()
            }
        };
        let file = entry.file.clone();
        let stack = Itertools::intersperse(
            iter::once(&*entry_func).chain(
                callstack
                    .into_iter()
                    .rev()
                    .map(|frame| env.def_name(frame.calling_function)),
            ),
            " -> ",
        )
        .collect();
        Self {
            stack,
            entry_func,
            file,
        }
    }
}

impl fmt::Display for AuthZVuln {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Authorization vulnerability")
    }
}

impl IntoVuln for AuthZVuln {
    fn into_vuln(self, reporter: &Reporter) -> Vulnerability {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        let mut hasher = DefaultHasher::new();
        self.file
            .iter()
            .skip_while(|comp| *comp != "src")
            .for_each(|comp| comp.hash(&mut hasher));
        self.entry_func.hash(&mut hasher);
        self.stack.hash(&mut hasher);
        Vulnerability {
            check_name: format!("Custom-Check-Authorization-{}", hasher.finish()),
            description: format!("Authorization bypass detected through {} in {:?}.", self.entry_func, self.file),
            recommendation: "Use the authorize API _https://developer.atlassian.com/platform/forge/runtime-reference/authorize-api/_ or manually authorize the user via the product REST APIs.",
            proof: format!("Unauthorized API call via asApp() found via {}", self.stack),
            severity: Severity::High,
            app_key: reporter.app_key().to_owned(),
            app_name: reporter.app_name().to_owned(),
            date: reporter.current_date(),
        }
    }
}

impl WithCallStack for AuthZVuln {
    fn add_call_stack(&mut self, _stack: Vec<DefId>) {}
}

impl<'cx> Runner<'cx> for AuthZChecker {
    type State = AuthorizeState;
    type Dataflow = AuthorizeDataflow;

    const NAME: &'static str = "Authorization";

    fn visit_intrinsic(
        &mut self,
        interp: &Interp<'cx, Self>,
        intrinsic: &'cx Intrinsic,
        _def: DefId,
        state: &Self::State,
        _operands: Option<SmallVec<[Operand; 4]>>,
    ) -> ControlFlow<(), Self::State> {
        match *intrinsic {
            Intrinsic::Authorize(_) => {
                debug!("authorize intrinsic found");
                ControlFlow::Continue(AuthorizeState::Yes)
            }
            Intrinsic::Fetch => ControlFlow::Continue(*state),
            Intrinsic::ApiCall(_) if *state != AuthorizeState::Yes => {
                let vuln = AuthZVuln::new(interp.callstack(), interp.env(), interp.entry());
                info!("Found a vuln!");
                self.vulns.push(vuln);
                ControlFlow::Break(())
            }
            Intrinsic::ApiCustomField if *state < AuthorizeState::CustomFieldOnly => {
                let vuln = AuthZVuln::new(interp.callstack(), interp.env(), interp.entry());
                info!("Found a vuln!");
                self.vulns.push(vuln);
                ControlFlow::Break(())
            }
            Intrinsic::SecretFunction(_)
            | Intrinsic::ApiCall(_)
            | Intrinsic::SafeCall(_)
            | Intrinsic::EnvRead
            | Intrinsic::UserFieldAccess
            | Intrinsic::ApiCustomField
            | Intrinsic::StorageRead => ControlFlow::Continue(*state),
        }
    }
}

impl<'cx> Checker<'cx> for AuthZChecker {
    type Vuln = AuthZVuln;
}

#[derive(Debug, PartialEq, Eq, Clone, Copy, PartialOrd, Ord)]
pub enum Authenticated {
    No,
    Yes,
}

impl JoinSemiLattice for Authenticated {
    const BOTTOM: Self = Self::No;

    #[inline]
    fn join_changed(&mut self, other: &Self) -> bool {
        let old = mem::replace(self, max(*other, *self));
        old == *self
    }

    #[inline]
    fn join(&self, other: &Self) -> Self {
        max(*other, *self)
    }
}

pub struct AuthenticateDataflow {
    needs_call: Vec<DefId>,
}

impl<'cx> Dataflow<'cx> for AuthenticateDataflow {
    type State = Authenticated;

    fn with_interp<C: crate::interp::Runner<'cx, State = Self::State>>(
        _interp: &Interp<'cx, C>,
    ) -> Self {
        Self { needs_call: vec![] }
    }

    fn transfer_intrinsic<C: crate::interp::Runner<'cx, State = Self::State>>(
        &mut self,
        _interp: &mut Interp<'cx, C>,
        _def: DefId,
        _loc: Location,
        _block: &'cx BasicBlock,
        intrinsic: &'cx Intrinsic,
        initial_state: Self::State,
        _operands: SmallVec<[crate::ir::Operand; 4]>,
    ) -> Self::State {
        match *intrinsic {
            Intrinsic::Authorize(_) => initial_state,
            Intrinsic::Fetch | Intrinsic::EnvRead | Intrinsic::StorageRead => {
                debug!("authenticated");
                Authenticated::Yes
            }
            Intrinsic::SecretFunction(_)
            | Intrinsic::ApiCall(_)
            | Intrinsic::ApiCustomField
            | Intrinsic::UserFieldAccess
            | Intrinsic::SafeCall(_) => initial_state,
        }
    }

    fn transfer_call<C: crate::interp::Runner<'cx, State = Self::State>>(
        &mut self,
        interp: &Interp<'cx, C>,
        def: DefId,
        loc: Location,
        _block: &'cx BasicBlock,
        callee: &'cx crate::ir::Operand,
        initial_state: Self::State,
        _operands: SmallVec<[crate::ir::Operand; 4]>,
    ) -> Self::State {
        let Some((callee_def, _body)) = self.resolve_call(interp, callee) else {
            return initial_state;
        };
        match interp.func_state(callee_def) {
            Some(state) => {
                if state == Authenticated::Yes {
                    debug!("Found call to authenticate at {def:?} {loc:?}");
                }
                initial_state.join(&state)
            }
            None => {
                let callee_name = interp.env().def_name(callee_def);
                let caller_name = interp.env().def_name(def);
                debug!("Found call to {callee_name} at {def:?} {caller_name}");
                self.needs_call.push(callee_def);
                initial_state
            }
        }
    }

    fn join_term<C: crate::interp::Runner<'cx, State = Self::State>>(
        &mut self,
        interp: &mut Interp<'cx, C>,
        def: DefId,
        block: &'cx BasicBlock,
        state: Self::State,
        worklist: &mut WorkList<DefId, BasicBlockId>,
    ) {
        self.super_join_term(interp, def, block, state, worklist);
        for def in self.needs_call.drain(..) {
            worklist.push_front_blocks(interp.env(), def, interp.call_all);
        }
    }
}

pub struct AuthenticateChecker {
    vulns: Vec<AuthNVuln>,
}

impl AuthenticateChecker {
    pub fn new() -> Self {
        Self { vulns: vec![] }
    }

    pub fn into_vulns(self) -> impl IntoIterator<Item = AuthNVuln> {
        self.vulns.into_iter()
    }
}

impl Default for AuthenticateChecker {
    fn default() -> Self {
        Self::new()
    }
}

impl<'cx> Runner<'cx> for AuthenticateChecker {
    type State = Authenticated;
    type Dataflow = AuthenticateDataflow;

    const NAME: &'static str = "Authentication";

    fn visit_intrinsic(
        &mut self,
        interp: &Interp<'cx, Self>,
        intrinsic: &'cx Intrinsic,
        _def: DefId,
        state: &Self::State,
        _operands: Option<SmallVec<[Operand; 4]>>,
    ) -> ControlFlow<(), Self::State> {
        match *intrinsic {
            Intrinsic::Authorize(_) => ControlFlow::Continue(*state),
            Intrinsic::Fetch | Intrinsic::EnvRead | Intrinsic::StorageRead => {
                debug!("authenticated");
                ControlFlow::Continue(Authenticated::Yes)
            }
            Intrinsic::ApiCall(_) | Intrinsic::ApiCustomField if *state == Authenticated::No => {
                let vuln = AuthNVuln::new(interp.callstack(), interp.env(), interp.entry());
                info!("Found a vuln!");
                self.vulns.push(vuln);
                ControlFlow::Break(())
            }
            Intrinsic::SecretFunction(_) => ControlFlow::Continue(*state),
            Intrinsic::ApiCall(_) | Intrinsic::UserFieldAccess | Intrinsic::ApiCustomField => {
                ControlFlow::Continue(*state)
            }
            Intrinsic::SafeCall(_) => ControlFlow::Continue(*state),
        }
    }
}

impl<'cx> Checker<'cx> for AuthenticateChecker {
    type Vuln = AuthNVuln;
}

#[derive(Debug)]
pub struct AuthNVuln {
    stack: String,
    entry_func: String,
    file: PathBuf,
}

impl AuthNVuln {
    fn new(callstack: Vec<Frame>, env: &Environment, entry: &EntryPoint) -> Self {
        let entry_func = match &entry.kind {
            EntryKind::Function(func) => func.clone(),
            EntryKind::Resolver(res, prop) => format!("{res}.{prop}"),
            EntryKind::Empty => {
                warn!("empty function");
                String::new()
            }
        };
        let file = entry.file.clone();
        let stack = Itertools::intersperse(
            iter::once(&*entry_func).chain(
                callstack
                    .into_iter()
                    .rev()
                    .map(|frame| env.def_name(frame.calling_function)),
            ),
            " -> ",
        )
        .collect();
        Self {
            stack,
            entry_func,
            file,
        }
    }
}

impl fmt::Display for AuthNVuln {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Authentication vulnerability")
    }
}

impl IntoVuln for AuthNVuln {
    fn into_vuln(self, reporter: &Reporter) -> Vulnerability {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        let mut hasher = DefaultHasher::new();
        self.file
            .iter()
            .skip_while(|comp| *comp != "src")
            .for_each(|comp| comp.hash(&mut hasher));
        self.entry_func.hash(&mut hasher);
        self.stack.hash(&mut hasher);
        Vulnerability {
            check_name: format!("Custom-Check-Authentication-{}", hasher.finish()),
            description: format!("Insufficient Authentication through webhook {} in {:?}.", self.entry_func, self.file),
            recommendation: "Properly authenticate incoming webhooks and ensure that any shared secrets are stored in Forge Secure Storage.",
            proof: format!("Unauthenticated API call via asApp() found via {}", self.stack),
            severity: Severity::High,
            app_key: reporter.app_key().to_owned(),
            app_name: reporter.app_name().to_owned(),
            date: reporter.current_date(),
        }
    }
}

impl WithCallStack for AuthNVuln {
    fn add_call_stack(&mut self, _stack: Vec<DefId>) {}
}

pub struct SecretDataflow {
    needs_call: Vec<DefId>,
}

#[derive(Debug, PartialEq, Eq, Clone, Copy, PartialOrd, Ord)]
pub enum SecretState {
    ALL,
}

impl JoinSemiLattice for SecretState {
    const BOTTOM: Self = Self::ALL;

    #[inline]
    fn join_changed(&mut self, other: &Self) -> bool {
        let old = mem::replace(self, max(*other, *self));
        old == *self
    }

    #[inline]
    fn join(&self, other: &Self) -> Self {
        max(*other, *self)
    }
}

impl<'cx> Dataflow<'cx> for SecretDataflow {
    type State = SecretState;

    fn with_interp<C: Runner<'cx, State = Self::State>>(
        _interp: &Interp<'cx, C>,
    ) -> Self {
        Self { needs_call: vec![] }
    }

    fn transfer_intrinsic<C: Runner<'cx, State = Self::State>>(
        &mut self,
        _interp: &mut Interp<'cx, C>,
        _def: DefId,
        _loc: Location,
        _block: &'cx BasicBlock,
        _intrinsic: &'cx Intrinsic,
        initial_state: Self::State,
        _operands: SmallVec<[Operand; 4]>,
    ) -> Self::State {
        initial_state
    }

    fn transfer_call<C: Runner<'cx, State = Self::State>>(
        &mut self,
        interp: &Interp<'cx, C>,
        _def: DefId,
        _loc: Location,
        _block: &'cx BasicBlock,
        callee: &'cx crate::ir::Operand,
        initial_state: Self::State,
        _operands: SmallVec<[crate::ir::Operand; 4]>,
    ) -> Self::State {
        let Some((callee_def, _body)) = self.resolve_call(interp, callee) else {
            return initial_state;
        };
        self.needs_call.push(callee_def);
        SecretState::ALL
    }

    fn join_term<C: Runner<'cx, State = Self::State>>(
        &mut self,
        interp: &mut Interp<'cx, C>,
        def: DefId,
        block: &'cx BasicBlock,
        state: Self::State,
        worklist: &mut WorkList<DefId, BasicBlockId>,
    ) {
        self.super_join_term(interp, def, block, state, worklist);
        for def in self.needs_call.drain(..) {
            worklist.push_front_blocks(interp.env(), def, interp.call_all);
        }
    }
}

pub struct SecretChecker {
    vulns: Vec<SecretVuln>,
}

impl SecretChecker {
    pub fn new() -> Self {
        Self { vulns: vec![] }
    }

    pub fn into_vulns(self) -> impl IntoIterator<Item = SecretVuln> {
        // TODO: make this an associated function on the Checker trait.
        self.vulns.into_iter()
    }
}

impl Default for SecretChecker {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug)]
pub struct SecretVuln {
    stack: String,
    entry_func: String,
    file: PathBuf,
}

impl SecretVuln {
    fn new(callstack: Vec<Frame>, env: &Environment, entry: &EntryPoint) -> Self {
        let entry_func = match &entry.kind {
            EntryKind::Function(func) => func.clone(),
            EntryKind::Resolver(res, prop) => format!("{res}.{prop}"),
            EntryKind::Empty => {
                warn!("empty function");
                String::new()
            }
        };
        let file = entry.file.clone();
        let stack = Itertools::intersperse(
            iter::once(&*entry_func).chain(
                callstack
                    .into_iter()
                    .rev()
                    .map(|frame| env.def_name(frame.calling_function)),
            ),
            " -> ",
        )
        .collect();
        Self {
            stack,
            entry_func,
            file,
        }
    }
}

impl fmt::Display for SecretVuln {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Hardcoded secret vulnerability")
    }
}

impl IntoVuln for SecretVuln {
    fn into_vuln(self, reporter: &Reporter) -> Vulnerability {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        let mut hasher = DefaultHasher::new();
        self.file
            .iter()
            .skip_while(|comp| *comp != "src")
            .for_each(|comp| comp.hash(&mut hasher));
        self.entry_func.hash(&mut hasher);
        self.stack.hash(&mut hasher);
        Vulnerability {
            check_name: format!("Hardcoded-Secret-{}", hasher.finish()),
            description: format!(
                "Hardcoded secret found within codebase {} in {:?}.",
                self.entry_func, self.file
            ),
            recommendation: "Use secrets as enviornment variables instead of hardcoding them.",
            proof: format!("Hardcoded secret found in found via {}", self.stack),
            severity: Severity::High,
            app_key: reporter.app_key().to_owned(),
            app_name: reporter.app_name().to_owned(),
            date: reporter.current_date(),
        }
    }
}

impl WithCallStack for SecretVuln {
    fn add_call_stack(&mut self, _stack: Vec<DefId>) {}
}

impl<'cx> Runner<'cx> for SecretChecker {
    type State = SecretState;
    type Dataflow = SecretDataflow;

    const NAME: &'static str = "Secret";

    fn visit_intrinsic(
        &mut self,
        interp: &Interp<'cx, Self>,
        intrinsic: &'cx Intrinsic,
        def: DefId,
        state: &Self::State,
        operands: Option<SmallVec<[Operand; 4]>>,
    ) -> ControlFlow<(), Self::State> {
        match intrinsic {
            Intrinsic::SecretFunction(package_data) => {
                if let Some(operand) = operands
                    .unwrap_or_default()
                    .get((package_data.secret_position - 1) as usize)
                {
                    {
                        if interp.check_for_const(operand, def) {
                            let vuln =
                                SecretVuln::new(interp.callstack(), interp.env(), interp.entry());
                            info!("Found a vuln!");
                            self.vulns.push(vuln);
                        }
                    }
                }
            }
            Intrinsic::Fetch => {
                if let Some(Operand::Var(Variable {
                    base: Base::Var(varid),
                    ..
                })) = operands.unwrap_or_default().get(1)
                {
                    let varid_argument =
                        if let Some(Value::Object(varid)) = interp.get_value(def, *varid, None) {
                            varid
                        } else {
                            varid
                        };
                    let headers_proj = projvec_from_str("Headers");
                    let headers_proj_lower = projvec_from_str("headers");
                    if let Some(Value::Object(varid)) = interp
                        .get_value(def, *varid_argument, Some(headers_proj))
                        .or_else(|| {
                            interp.get_value(def, *varid_argument, Some(headers_proj_lower))
                        })
                    {
                        let auth_proj = projvec_from_str("Authorization");
                        let aut_proj_lower = projvec_from_str("authorization");
                        if let Some(Value::Const(_) | Value::Phi(_)) = interp
                            .get_value(def, *varid, Some(auth_proj))
                            .or_else(|| interp.get_value(def, *varid, Some(aut_proj_lower)))
                        {
                            let vuln =
                                SecretVuln::new(interp.callstack(), interp.env(), interp.entry());
                            info!("Found a vuln!");
                            self.vulns.push(vuln);
                        }
                    }
                }
            }

            _ => {}
        }

        ControlFlow::Continue(*state)
    }
}

impl<'cx> Checker<'cx> for SecretChecker {
    type Vuln = SecretVuln;
}

pub struct PermissionDataflow {
    needs_call: Vec<(DefId, Vec<Operand>)>,
    pub varid_to_value: FxHashMap<(DefId, VarId, Option<Projection>), Value>,
    pub defid_to_value: FxHashMap<DefId, Value>,
}

impl PermissionDataflow {
    fn handle_second_arg(&self, value: &Value, intrinsic_argument: &mut IntrinsicArguments) {
        match value {
            Value::Const(Const::Literal(lit)) => {
                intrinsic_argument.second_arg = Some(vec![lit.clone()]);
            }
            Value::Phi(phi_val) => {
                intrinsic_argument.second_arg = Some(
                    phi_val
                        .iter()
                        .filter_map(|data| {
                            if let Const::Literal(lit) = data {
                                Some(lit.clone())
                            } else {
                                None
                            }
                        })
                        .collect_vec(),
                )
            }
            _ => {}
        }
    }
}

impl WithCallStack for PermissionVuln {
    fn add_call_stack(&mut self, _stack: Vec<DefId>) {}
}

#[derive(Debug, Default, Clone)]
pub struct IntrinsicArguments {
    name: Option<IntrinsicName>,
    first_arg: Option<Vec<String>>,
    second_arg: Option<Vec<String>>,
}

impl<'cx> Dataflow<'cx> for PermissionDataflow {
    type State = PermissionTest;

    fn with_interp<C: crate::interp::Runner<'cx, State = Self::State>>(
        _interp: &Interp<'cx, C>,
    ) -> Self {
        Self {
            needs_call: vec![],
            varid_to_value: FxHashMap::default(),
            defid_to_value: FxHashMap::default(),
        }
    }

    fn transfer_intrinsic<C: crate::interp::Runner<'cx, State = Self::State>>(
        &mut self,
        interp: &mut Interp<'cx, C>,
        _def: DefId,
        _loc: Location,
        _block: &'cx BasicBlock,
        intrinsic: &'cx Intrinsic,
        initial_state: Self::State,
        operands: SmallVec<[Operand; 4]>,
    ) -> Self::State {
        let mut intrinsic_argument = IntrinsicArguments::default();
        if let Intrinsic::ApiCall(name) | Intrinsic::SafeCall(name) | Intrinsic::Authorize(name) =
            intrinsic
        {
            intrinsic_argument.name = Some(*name);
            let (first, second) = (operands.first(), operands.get(1));
            if let Some(operand) = first {
                match operand {
                    Operand::Lit(lit) => {
                        if &Literal::Undef != lit {
                            intrinsic_argument.first_arg = Some(vec![lit.to_string()]);
                        }
                    }
                    Operand::Var(var) => {
                        if let Base::Var(varid) = var.base {
                            if let Some(value) = interp.get_value(_def, varid, None) {
                                add_elements_to_intrinsic_struct(
                                    value,
                                    intrinsic_argument.first_arg.insert(vec![]),
                                );
                            } else if let Some(VarKind::GlobalRef(def)) =
                                interp.body().vars.get(varid)
                            {
                                if let Some(value @ Value::Const(_)) =
                                    interp.value_manager.defid_to_value.get(def)
                                {
                                    add_elements_to_intrinsic_struct(
                                        value,
                                        intrinsic_argument.first_arg.insert(vec![]),
                                    );
                                }
                            }
                        }
                    }
                }
            }
            if let Some(Operand::Var(variable)) = second {
                if let Base::Var(varid) = variable.base {
                    let mut method_vec = ProjectionVec::new();
                    method_vec.push(Projection::Known("method".into()));
                    if let Some(value) = interp.get_value(_def, varid, Some(method_vec)) {
                        self.handle_second_arg(value, &mut intrinsic_argument);
                    }
                }
            }

            let mut permissions_within_call: Vec<String> = vec![];
            let intrinsic_func_type = intrinsic_argument.name.unwrap();

            if intrinsic_argument.first_arg.is_none() {
                interp.permissions.drain(..);
            } else {
                intrinsic_argument
                    .first_arg
                    .iter()
                    .for_each(|first_arg_vec| {
                        if let Some(second_arg_vec) = intrinsic_argument.second_arg.clone() {
                            first_arg_vec.iter().for_each(|first_arg| {
                                let first_arg = first_arg.replace(&['\"'][..], "");
                                second_arg_vec.iter().for_each(|second_arg| {
                                    if intrinsic_func_type == IntrinsicName::RequestConfluence {
                                        let permissions = check_url_for_permissions(
                                            interp.confluence_permission_resolver,
                                            interp.confluence_regex_map,
                                            translate_request_type(Some(second_arg)),
                                            &first_arg,
                                        );
                                        permissions_within_call.extend_from_slice(&permissions)
                                    } else if intrinsic_func_type == IntrinsicName::RequestJira {
                                        let permissions = check_url_for_permissions(
                                            interp.jira_permission_resolver,
                                            interp.jira_regex_map,
                                            translate_request_type(Some(second_arg)),
                                            &first_arg,
                                        );
                                        permissions_within_call.extend_from_slice(&permissions)
                                    }
                                })
                            })
                        } else {
                            first_arg_vec.iter().for_each(|first_arg| {
                                let first_arg = first_arg.replace(&['\"'][..], "");
                                if intrinsic_func_type == IntrinsicName::RequestConfluence {
                                    let permissions = check_url_for_permissions(
                                        interp.confluence_permission_resolver,
                                        interp.confluence_regex_map,
                                        RequestType::Get,
                                        &first_arg,
                                    );
                                    permissions_within_call.extend_from_slice(&permissions)
                                } else if intrinsic_func_type == IntrinsicName::RequestJira {
                                    let permissions = check_url_for_permissions(
                                        interp.jira_permission_resolver,
                                        interp.jira_regex_map,
                                        RequestType::Get,
                                        &first_arg,
                                    );
                                    permissions_within_call.extend_from_slice(&permissions)
                                }
                            })
                        }
                    });

                interp
                    .permissions
                    .retain(|permissions| !permissions_within_call.contains(permissions));
            }

            // remvove all permissions that it finds
        }
        initial_state
    }

    fn transfer_call<C: crate::interp::Runner<'cx, State = Self::State>>(
        &mut self,
        interp: &Interp<'cx, C>,
        def: DefId,
        _loc: Location,
        _block: &'cx BasicBlock,
        callee: &'cx crate::ir::Operand,
        initial_state: Self::State,
        operands: SmallVec<[crate::ir::Operand; 4]>,
    ) -> Self::State {
        let Some((callee_def, _body)) = self.resolve_call(interp, callee) else {
            return initial_state;
        };

        let callee_name = interp.env().def_name(callee_def);
        let caller_name = interp.env().def_name(def);
        debug!("Found call to {callee_name} at {def:?} {caller_name}");
        self.needs_call.push((callee_def, operands.into_vec()));
        initial_state
    }

    fn transfer_block<C: Runner<'cx, State = Self::State>>(
        &mut self,
        interp: &mut Interp<'cx, C>,
        def: DefId,
        bb: BasicBlockId,
        block: &'cx BasicBlock,
        initial_state: Self::State,
        _arguments: Option<Vec<Value>>,
    ) -> Self::State {
        let mut state = initial_state;

        for (stmt, inst) in block.iter().enumerate() {
            let loc = Location::new(bb, stmt as u32);
            state = self.transfer_inst(interp, def, loc, block, inst, state);
        }
        state
    }

    fn join_term<C: crate::interp::Runner<'cx, State = Self::State>>(
        &mut self,
        interp: &mut Interp<'cx, C>,
        def: DefId,
        block: &'cx BasicBlock,
        state: Self::State,
        worklist: &mut WorkList<DefId, BasicBlockId>,
    ) {
        self.super_join_term(interp, def, block, state, worklist);
        for (def, _arguments) in self.needs_call.drain(..) {
            worklist.push_front_blocks(interp.env(), def, interp.call_all);
        }
    }
}

pub struct PermissionChecker {
    pub visit: bool,
    pub vulns: Vec<PermissionVuln>,
}

impl PermissionChecker {
    pub fn new() -> Self {
        Self {
            visit: false,
            vulns: vec![],
        }
    }

    pub fn into_vulns(
        mut self,
        permissions: Vec<String>,
    ) -> impl IntoIterator<Item = PermissionVuln> {
        if !permissions.is_empty() {
            self.vulns.resize(1, PermissionVuln::new(permissions));
        }
        self.vulns
    }
}

impl Default for PermissionChecker {
    fn default() -> Self {
        PermissionChecker::new()
    }
}

impl fmt::Display for PermissionVuln {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Authentication vulnerability")
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Copy, PartialOrd, Ord, Default)]
pub enum PermissionTest {
    #[default]
    Yes,
    No,
}

impl JoinSemiLattice for PermissionTest {
    const BOTTOM: Self = Self::Yes;

    #[inline]
    fn join_changed(&mut self, other: &Self) -> bool {
        let old = mem::replace(self, self.join(other));
        old != *self
    }

    #[inline]
    fn join(&self, other: &Self) -> Self {
        max(*other, *self)
    }
}

#[derive(Debug, Clone)]
pub struct PermissionVuln {
    unused_permissions: Vec<String>,
}

impl PermissionVuln {
    pub fn new(unused_permissions: Vec<String>) -> PermissionVuln {
        PermissionVuln { unused_permissions }
    }
}

pub struct DefintionAnalysisRunner {
    pub needs_call: Vec<(DefId, Vec<Operand>, Vec<Value>)>,
}

impl<'cx> Runner<'cx> for PermissionChecker {
    type State = PermissionTest;
    type Dataflow = PermissionDataflow;

    fn visit_intrinsic(
        &mut self,
        _interp: &Interp<'cx, Self>,
        _intrinsic: &'cx Intrinsic,
        _def: DefId,
        state: &Self::State,
        _operands: Option<SmallVec<[Operand; 4]>>,
    ) -> ControlFlow<(), Self::State> {
        ControlFlow::Continue(*state)
    }
}

impl<'cx> Checker<'cx> for PermissionChecker {
    type Vuln = PermissionVuln;
}

impl IntoVuln for PermissionVuln {
    fn into_vuln(self, reporter: &Reporter) -> Vulnerability {
        Vulnerability {
            check_name: "Least-Privilege".to_owned(),
            description: format!(
                "Unused permissions listed in manifest file: {:?}",
                self.unused_permissions
            ),
            recommendation: "Remove permissions in manifest file that are not needed.",
            proof: format!(
                "Unused permissions found in manifest.yml: {:?}",
                self.unused_permissions
            ),
            severity: Severity::Low,
            app_key: reporter.app_key().to_string(),
            app_name: reporter.app_name().to_string(),
            date: reporter.current_date(),
        }
    }
}

impl<'cx> Runner<'cx> for DefintionAnalysisRunner {
    type State = PermissionTest;
    type Dataflow = DefintionAnalysisRunner;
    const NAME: &'static str = "DefinitionAnalysis";

    fn visit_intrinsic(
        &mut self,
        _interp: &Interp<'cx, Self>,
        _intrinsic: &'cx Intrinsic,
        _def: DefId,
        _state: &Self::State,
        _operands: Option<SmallVec<[Operand; 4]>>,
    ) -> ControlFlow<(), Self::State> {
        ControlFlow::Break(())
    }
}

impl DefintionAnalysisRunner {
    pub fn new() -> Self {
        Self {
            needs_call: Vec::default(),
        }
    }
}

impl Default for DefintionAnalysisRunner {
    fn default() -> Self {
        Self::new()
    }
}

impl<'cx> Dataflow<'cx> for DefintionAnalysisRunner {
    type State = PermissionTest;

    fn with_interp<C: crate::interp::Runner<'cx, State = Self::State>>(
        _interp: &Interp<'cx, C>,
    ) -> Self {
        Self { needs_call: vec![] }
    }

    fn transfer_intrinsic<C: crate::interp::Runner<'cx, State = Self::State>>(
        &mut self,
        _interp: &mut Interp<'cx, C>,
        _def: DefId,
        _loc: Location,
        _block: &'cx BasicBlock,
        _intrinsic: &'cx Intrinsic,
        initial_state: Self::State,
        _operands: SmallVec<[crate::ir::Operand; 4]>,
    ) -> Self::State {
        initial_state
    }

    fn transfer_call<C: crate::interp::Runner<'cx, State = Self::State>>(
        &mut self,
        interp: &Interp<'cx, C>,
        def: DefId,
        _loc: Location,
        _block: &'cx BasicBlock,
        callee: &'cx crate::ir::Operand,
        initial_state: Self::State,
        operands: SmallVec<[crate::ir::Operand; 4]>,
    ) -> Self::State {
        let Some((callee_def, _body)) = self.resolve_call(interp, callee) else {
            return initial_state;
        };

        let callee_name = interp.env().def_name(callee_def);
        let caller_name = interp.env().def_name(def);
        debug!("Found call to {callee_name} at {def:?} {caller_name}");

        let mut all_values_to_be_pushed = vec![];

        for operand in &operands {
            match operand.clone() {
                Operand::Lit(_) => {
                    if let Some(lit_value) = convert_operand_to_raw(&operand.clone()) {
                        all_values_to_be_pushed.push(Value::Const(Const::Literal(lit_value)));
                    } else {
                        all_values_to_be_pushed.push(Value::Unknown)
                    }
                }
                Operand::Var(var) => match var.base {
                    Base::Var(varid) => {
                        if let Some(value) = interp.get_value(def, varid, Some(var.projections)) {
                            all_values_to_be_pushed.push(value.clone());
                        } else {
                            all_values_to_be_pushed.push(Value::Unknown)
                        }
                    }
                    _ => all_values_to_be_pushed.push(Value::Unknown),
                },
            }
        }
        self.needs_call
            .push((callee_def, operands.into_vec(), all_values_to_be_pushed));
        initial_state
    }

    fn transfer_inst<C: Runner<'cx, State = Self::State>>(
        &mut self,
        interp: &mut Interp<'cx, C>,
        def: DefId,
        loc: Location,
        block: &'cx BasicBlock,
        inst: &'cx Inst,
        initial_state: Self::State,
    ) -> Self::State {
        match inst {
            Inst::Expr(rvalue) => {
                self.transfer_rvalue(interp, def, loc, block, rvalue, initial_state)
            }
            Inst::Assign(var, rvalue) => {
                if let Base::Var(varid) = var.base {
                    match rvalue {
                        Rvalue::Call(Operand::Var(variable), _) => {
                            if let Base::Var(varid) = variable.base {
                                if let Some(VarKind::GlobalRef(defid)) =
                                    interp.body().vars.get(varid)
                                {
                                    if let Base::Var(varid_to_assign) = var.base {
                                        interp
                                            .value_manager
                                            .expected_return_values
                                            .insert(*defid, (def, varid_to_assign));
                                    }
                                }
                            }
                        }
                        Rvalue::Read(_operand) => {
                            if let Rvalue::Read(Operand::Lit(Literal::Str(str))) = rvalue {
                                if let Base::Var(varid) = var.base {
                                    if let Some(VarKind::GlobalRef(def)) =
                                        interp.body().vars.get(varid)
                                    {
                                        interp.value_manager.defid_to_value.insert(
                                            *def,
                                            Value::Const(Const::Literal(str.to_string())),
                                        );
                                    } else if let Some(VarKind::LocalDef(def)) =
                                        interp.body().vars.get(varid)
                                    {
                                        interp.value_manager.defid_to_value.insert(
                                            *def,
                                            Value::Const(Const::Literal(str.to_string())),
                                        );
                                    } else if let Some(&VarKind::Temp {
                                        parent: Some(defid_parent),
                                    }) = interp.body().vars.get(varid)
                                    {
                                        interp.value_manager.defid_to_value.insert(
                                            defid_parent,
                                            Value::Const(Const::Literal(str.to_string())),
                                        );
                                    }
                                }
                            }
                            /* should be expanded to include all of the cases ... */

                            self.add_variable(interp, var, &varid, def, rvalue);
                        }
                        Rvalue::Template(_) => {
                            self.add_variable(interp, var, &varid, def, rvalue);
                        }
                        _ => {}
                    }
                }
                self.transfer_rvalue(interp, def, loc, block, rvalue, initial_state)
            }
        }
    }

    fn transfer_block<C: Runner<'cx, State = Self::State>>(
        &mut self,
        interp: &mut Interp<'cx, C>,
        def: DefId,
        bb: BasicBlockId,
        block: &'cx BasicBlock,
        initial_state: Self::State,
        arguments: Option<Vec<Value>>,
    ) -> Self::State {
        let mut state = initial_state;
        let mut function_var = interp.curr_body.get().unwrap().vars.clone();
        function_var.pop();
        if let Some(args) = arguments {
            let mut args = args.clone();
            args.reverse();
            for (varid, varkind) in function_var.iter_enumerated() {
                if let VarKind::Arg(_) = varkind {
                    if let Some(operand) = args.pop() {
                        interp.add_value(def, varid, operand.clone());
                        interp
                            .body()
                            .vars
                            .iter_enumerated()
                            .for_each(|(varid_alt, varkind_alt)| {
                                let defult_projections = Variable::from(varid_alt);

                                if let (Some(defid_alt), Some(defid)) = (
                                    get_defid_from_varkind(varkind_alt),
                                    get_defid_from_varkind(varkind),
                                ) {
                                    if defid == defid_alt && varid_alt != varid {
                                        interp.add_value_with_projection(
                                            def,
                                            varid_alt,
                                            operand.clone(),
                                            defult_projections.projections,
                                        );
                                    }
                                }
                            })
                    }
                }
            }
        }

        for (stmt, inst) in block.iter().enumerate() {
            let loc = Location::new(bb, stmt as u32);
            state = self.transfer_inst(interp, def, loc, block, inst, state);
        }

        for (varid, varkind) in interp.body().vars.clone().iter_enumerated() {
            if &VarKind::Ret == varkind {
                if let Some((defid_calling_func, varid_calling_func)) =
                    interp.value_manager.expected_return_values.get(&def)
                {
                    if let Some(value) = interp.get_value(def, varid, None) {
                        interp.add_value(*defid_calling_func, *varid_calling_func, value.clone());
                    }
                }
            }
        }

        state
    }

    fn add_variable<C: Runner<'cx, State = Self::State>>(
        &mut self,
        interp: &mut Interp<'cx, C>,
        lval: &Variable,
        varid: &VarId,
        def: DefId,
        rvalue: &Rvalue,
    ) {
        match rvalue {
            Rvalue::Read(operand) => {
                if let Operand::Var(variable) = operand {
                    if let Base::Var(varid_rval) = variable.base {
                        if interp.is_obj(varid_rval) {
                            interp.add_value_with_projection(
                                def,
                                *varid,
                                Value::Object(varid_rval),
                                lval.projections.clone(),
                            )
                        } else {
                            interp.value_manager.varid_to_value.clone().iter().for_each(
                                |((_defid, varid_rval_potential), value)| {
                                    if varid_rval_potential == &varid_rval && _defid == &def {
                                        interp.add_value(
                                            def,
                                            *varid,
                                            value.clone(),
                                        )
                                    }
                                },
                            );
                            interp.value_manager.varid_to_value_proj.clone().iter().for_each(
                                |((_defid, varid_rval_potential, _projection), value)| {
                                    if varid_rval_potential == &varid_rval && _defid == &def {
                                        interp.add_value_with_projection(
                                            def,
                                            *varid,
                                            value.clone(),
                                            lval.projections.clone(),
                                        )
                                    }
                                },
                            );
                        }
                    }
                } else if let Some(value) =
                    get_prev_value(interp.get_value(def, *varid, Some(lval.projections.clone())))
                {
                    self.insert_value(interp, operand, lval, varid, def, Some(value));
                } else {
                    self.insert_value(interp, operand, lval, varid, def, None);
                }
            }
            Rvalue::Template(template) => {
                let quasis_joined: String =
                    template.quasis.iter().map(ToString::to_string).collect();
                let mut all_potential_values = vec![String::from("")];
                if template.exprs.is_empty() {
                    all_potential_values.push(quasis_joined.clone());
                } else if template.exprs.len() <= 3 {
                    let mut all_values = vec![String::from("")];

                    for (i, expr) in template.exprs.iter().enumerate() {
                        if let Some(quasis) = template.quasis.get(i) {
                            all_values = all_values
                                .iter()
                                .map(|value| format!("{value}{quasis}"))
                                .collect();
                        }
                        let mut new_values = vec![];

                        let values = self.get_str_from_expr(interp, expr.clone(), def);
                        if !values.is_empty() {
                            for str_value in values {
                                for value in &all_values {
                                    if let Some(str) = &str_value {
                                        new_values.push(value.clone() + &**str)
                                    } else {
                                        new_values.push(value.clone())
                                    }
                                }
                            }
                            all_values = new_values
                        }
                    }

                    if template.quasis.len() > template.exprs.len() {
                        let last_elem = template.quasis.last().unwrap();
                        all_values = all_values
                            .iter()
                            .map(|value| format!("{value}{last_elem}"))
                            .collect();
                    }

                    all_potential_values = all_values;
                }
                match <[_; 1]>::try_from(all_potential_values) {
                    Ok([value]) => {
                        interp.add_value(def, *varid, Value::Const(Const::Literal(value)));
                    }
                    Err(all_potential_values) if !all_potential_values.is_empty() => {
                        let value = Value::Phi(
                            all_potential_values
                                .into_iter()
                                .map(Const::Literal)
                                .collect(),
                        );
                        interp.add_value(def, *varid, value);
                    }
                    Err(_) => {}
                }
            }
            Rvalue::Bin(binop, op1, op2) => {
                if binop == &BinOp::Add {
                    let val1 = if let Some(val) = get_str_from_operand(op1) {
                        Some(Value::Const(Const::Literal(val)))
                    } else {
                        self.get_values_from_operand(interp, def, op2)
                    };
                    let val2 = if let Some(val) = get_str_from_operand(op2) {
                        Some(Value::Const(Const::Literal(val)))
                    } else {
                        self.get_values_from_operand(interp, def, op2)
                    };
                    let mut new_vals = vec![];
                    if let (Some(val1), Some(val2)) = (val1.clone(), val2.clone()) {
                        match val1 {
                            Value::Const(const_val) => {
                                add_const_to_val_vec(&val2, &const_val, &mut new_vals)
                            }
                            Value::Phi(phi_val) => phi_val
                                .iter()
                                .for_each(|val1| add_const_to_val_vec(&val2, val1, &mut new_vals)),
                            _ => {}
                        }
                        interp.add_value_with_projection(
                            def,
                            *varid,
                            return_value_from_string(new_vals),
                            Variable::from(*varid).projections,
                        )
                    } else if let Some(val1) = val1 {
                        interp.add_value(def, *varid, val1);
                    } else if let Some(val2) = val2 {
                        interp.add_value(def, *varid, val2);
                    }
                }
            }
            _ => {}
        }
    }

    fn insert_value<C: Runner<'cx, State = Self::State>>(
        &mut self,
        interp: &mut Interp<'cx, C>,
        operand: &Operand,
        lval: &Variable,
        varid: &VarId,
        def: DefId,
        prev_values: Option<Vec<Const>>,
    ) {
        match operand {
            Operand::Lit(lit) => {
                if &Literal::Undef != lit {
                    if let Some(prev_values) = prev_values {
                        if let Some(lit_value) = convert_operand_to_raw(operand) {
                            let const_value = Const::Literal(lit_value);
                            let mut all_values = prev_values.clone();
                            all_values.push(const_value);
                            let value = Value::Phi(all_values);
                            interp.add_value_with_projection(
                                def,
                                *varid,
                                value,
                                lval.projections.clone(),
                            );
                        }
                    } else if let Some(lit_value) = convert_operand_to_raw(operand) {
                        let value = Value::Const(Const::Literal(lit_value));
                        interp.add_value_with_projection(
                            def,
                            *varid,
                            value,
                            lval.projections.clone(),
                        );
                    }
                }
            }
            Operand::Var(var) => {
                if let Base::Var(prev_varid) = var.base {
                    let potential_varkind = &interp.curr_body.get().unwrap().vars.get(prev_varid);
                    if let Some(VarKind::LocalDef(local_defid)) = potential_varkind {
                        if let Some(class) = self.read_class_from_object(interp, *local_defid) {
                            if let Some(prev_values) = prev_values {
                                let const_value = Const::Object(class.clone());
                                let mut all_values = prev_values.clone();
                                all_values.push(const_value);
                                let value = Value::Phi(all_values);
                                interp.add_value_with_projection(
                                    def,
                                    *varid,
                                    value,
                                    lval.projections.clone(),
                                );
                            } else {
                                let value = Value::Const(Const::Object(class));
                                interp.add_value_with_projection(
                                    def,
                                    *varid,
                                    value,
                                    lval.projections.clone(),
                                );
                            }
                        }
                    } else if let Some(potential_value) = interp.get_value(def, prev_varid, None) {
                        interp.add_value_with_projection(
                            def,
                            *varid,
                            potential_value.clone(),
                            var.projections.clone(),
                        );
                    }
                }
            }
        }
    }

    fn join_term<C: Runner<'cx, State = Self::State>>(
        &mut self,
        interp: &mut Interp<'cx, C>,
        def: DefId,
        block: &'cx BasicBlock,
        state: Self::State,
        worklist: &mut WorkList<DefId, BasicBlockId>,
    ) {
        self.super_join_term(interp, def, block, state, worklist);
        for (def, _arguments, values) in self.needs_call.drain(..) {
            worklist.push_front_blocks(interp.env(), def, interp.call_all);
            interp.callstack_arguments.push(values.clone());
        }
    }
}
