# AI skill scoping checklist

One page. Fill it in **before** building or enabling an AI skill. If a line can't be answered, the skill isn't ready.
The right-hand column shows the answers for the demo KB article skill, so you can see the level of detail expected.

| # | Question | Write the answer here | Example: KB article skill |
|---|---|---|---|
| 1 | **Purpose.** What single job does it do? One sentence. | | Turn one resolved incident into a *draft* KB article for review. |
| 2 | **Allowed data.** Which exact fields may it read? (A list, not "tickets".) | | category, short_description, symptoms, cause, resolution_steps, notes |
| 3 | **Forbidden data.** What must it never see, and what happens if it appears anyway? | | Reporter name/email/phone, hostnames, ticket numbers, internal comments: dropped. SSN-like text and credentials: request refused. |
| 4 | **Who can run it?** Which roles? Who can *not*? | | Authors only. Viewers and approvers cannot run it. |
| 5 | **What can it change?** Name every place it may write. Default answer is "nothing". | | Only `pending_review/`. Never the published KB, never `approved/`. |
| 6 | **What can it never change?** List the systems it must have no path to. | | Published KB, ticketing system, directory services. |
| 7 | **Approval step.** Who reviews output, and can the author approve their own? | | A different person with the approver role. Self-approval is refused. |
| 8 | **Untrusted input.** Where does outside text come from, and what stops it acting as instructions? | | Ticket text is data only. Instruction-like sentences are removed and logged. Skill is a fixed template with no tools. |
| 9 | **Logging.** What is logged? What must *never* be logged? Can logging be turned off? | | Who, what, when, skill, decision, hashes, counts, field names. No ticket content. Cannot be disabled. |
| 10 | **Failure behaviour.** What happens on any error or doubt? | | Fail closed: deny, log the reason code, write nothing. |
| 11 | **Rollback / off-switch.** How do you undo its output and how do you stop it? | | Nothing is published without approval, so undo = reject the draft. Stop = delete or empty its manifest (default deny). |
| 12 | **Test evidence.** Which tests prove items 2 to 11? | | See the table in the README. |

## Quick sanity checks

- [ ] The permission set lives in a file a human can read in one minute.
- [ ] Limits are enforced in **code**, not in the prompt.
- [ ] A new skill with an empty manifest can do **nothing**.
- [ ] The default mode is a dry run; writing needs an explicit flag.
- [ ] Output goes to a review area first; publishing is a separate, logged, human step.
- [ ] The person who asked for the output is not the person who approves it.
- [ ] The log records denials as well as successes.
- [ ] You have written down what the skill does **not** protect against.

## Review triggers

Re-run this checklist whenever someone wants to: add a field, add a place to write, add a role, connect a new data source,
swap the model, or reduce logging. Each of those is a scope change and should be a reviewed change to the manifest.
