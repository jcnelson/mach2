# Mach2: Self-custodial Bitcoin DeFi

Mach2 is a prototype system for building self-custodial Bitcoin DeFi systems on
Stacks.  BTC providers lock their BTC on-chain for a certain period of time, and while
it is locked, they work within Mach2 to instantiate a wrapped "M2BTC" token
which is backed by pre-signed, post-dated Bitcoin transactions.  As users
transfer M2BTC in Mach2, they append new transactions to a directed
acyclic graph (DAG) of off-chain Bitcoin transactions rooted at one or more BTC
provider lock-up transactions.  If the BTC provider opts not to extend their
lock time, then the DAG becomes mineable, and all M2BTC holders receive their
corresponding BTC.

BTC and Stacks assets can both be locked up on their respective chains and
instantiated with Mach2, allowing asset trades to happen as fast as Mach2 can
handle them.

Mach2 employs a decentralized network service called a _cosigner_, which ensures
that DAG transactions are only produced consequent to Clarity code execution.
While BTC providers are guaranteed unilateral exit by way of waiting for their
lock-time to expire, M2BTC recipients rely on the cosigner to remain honest and
preserve the structure of the DAG until it can be mined on Bitcoin.

More information will be provided as it becomes available.

## Implementation Checklist

- [X] Bitcoin peg-in transaction to lock BTC
- [X] Clarity smart contract for verifying a BTC lock-up
- [ ] Clarity smart contract for instantiating StackerDBs for Mach2
  communication between users and the Mach2 cosigner.
- [ ] Mach2 smart contract for locking Stacks assets
- [ ] Off-chain DAG database for both BTC and wrapped Stacks assets
- [ ] 2-phase commit cosigner for cosigning DAG transactions
- [ ] CLI app for spending M2BTC between Mach2 users by appending DAG transactions
- [ ] Instrumented Clarity VM with M2BTC keywords for transferring M2BTC, escrowing
  M2BTC, and querying M2BTC balances at given Bitcoin heights
- [ ] Simple lending app on Mach2
- [ ] Simple AMM on Mach2
