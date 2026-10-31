//! Owned child status aggregation; no terminal or process effects here.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum State {
    Running,
    Stopped,
    Done,
}
pub(crate) struct Members(Vec<(i32, State)>);
impl Members {
    pub(crate) fn new() -> Self {
        Self(Vec::new())
    }
    pub(crate) fn push(&mut self, pid: i32) {
        self.0.push((pid, State::Running));
    }
    pub(crate) fn entries(&self) -> impl Iterator<Item = (i32, State)> + '_ {
        self.0.iter().copied()
    }
    pub(crate) fn update(&mut self, pid: i32, state: State) -> bool {
        let Some(entry) = self.0.iter_mut().find(|entry| entry.0 == pid) else {
            return false;
        };
        if entry.1 == State::Done {
            return state == State::Done;
        }
        entry.1 = state;
        true
    }
    pub(crate) fn resume(&mut self) {
        for (_, state) in &mut self.0 {
            if *state == State::Stopped {
                *state = State::Running;
            }
        }
    }
    pub(crate) fn state(&self) -> State {
        if self.0.iter().all(|entry| entry.1 == State::Done) {
            State::Done
        } else if self.0.iter().all(|entry| entry.1 != State::Running) {
            State::Stopped
        } else {
            State::Running
        }
    }
}
