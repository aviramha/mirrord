//! Routing outgoing sockets through locally stack or remote (agent)-stack
//! based on the destination address and/or protocol.
//! Rules for matching are score-based, the highest score wins.
//! In order for a rule to have a score all of its parameters need to match.

use crate::socket::UserSocket;

/// Type to use for scores.
type Score = u8;

pub(crate) enum Verdict {
    /// Connect to the address via the agent (remote stack).
    Remote,
    /// Connect to the address via the local stack. (Passthrough)
    Local,
}

/// Struct that holds the score of a rule match.
pub(crate) struct MatchScore {
    /// Sum of all scores of the matched parameters.
    score: Score,
    /// The verdict of the match.
    verdict: Verdict,
}

/// Supported protocols
pub(crate) enum Protocol {
    Tcp,
    Udp,
}

/// User defined rule that can be used to match against a connection.
pub(crate) struct Rule {
    protocol: Option<Protocol>,
    dest_ip: Option<Ip>,
    dest_port: Option<Port>,
    verdict: Verdict,
}

/// Trait for a parameter that can be matched against a connection.
/// Typically part of a `Rule`
trait ParameterMatch {
    /// Each parameter has a score
    const SCORE: Score;

    /// Return a score for the parameter match.
    fn score(&self, socket: &UserSocket) -> Score;
}

/// This makes it possible to call `.score` on `Option` making code nicer.
impl<T> ParameterMatch for Option<T>
where
    T: ParameterMatch,
{
    const SCORE: Score = T::SCORE;

    fn score(&self, socket: &UserSocket) -> Score {
        match self {
            Some(param) => param.score(socket),
            None => 0,
        }
    }
}
