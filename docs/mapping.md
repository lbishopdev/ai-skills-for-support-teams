# Mapping these ideas to enterprise platforms (conceptual)

> **Status: conceptual and unverified.** I have not built anything in a ServiceNow or Microsoft 365 tenant,
> and I cannot verify product details, feature names, licensing or availability from here. Product names are used
> as "the place I would look for the equivalent control", not as claims about how those products work.
> Treat every row as a question to confirm with the platform's own documentation and the people who administer it.

The point of this repo is the *pattern*: narrow scope, enforced outside the model, with approval and an audit trail.
Platforms tend to offer pieces of the same pattern under their own names.

## How to read the table

- **Conceptual** = I believe this is the analogous idea, but I have not confirmed it hands-on.
- **Ask** = the question I would put to whoever administers the platform.

## 1. ServiceNow (Now Assist Skill Kit, AI Agent Studio)

| Idea in this repo | Likely analogue | Label | Ask |
|---|---|---|---|
| **Scope manifest** (purpose, inputs, roles, writes) | The definition of a custom skill or agent: its inputs, the data it retrieves, the tools or actions it can call, and who can run it | Conceptual | Where is each of those set, and can they be reviewed and versioned like code? |
| **Field allow-list** (drop everything not named) | Which tables and fields a skill can read, enforced by the platform's normal access controls rather than only by the prompt | Conceptual | Does the skill run as the invoking user or as a service identity, and are field-level restrictions applied to what the model is sent? |
| **Default deny** | A new skill or agent having no data or tool access until explicitly granted | Conceptual | What does a brand-new skill get by default? |
| **Roles** (viewer / author / approver) | Platform roles that control who can build, run, publish and activate skills | Conceptual | Which roles can publish vs. only test, and can the builder also activate their own work? |
| **Approval gate** (`pending_review` -> `approved`) | Draft vs. published states for knowledge articles, and approval workflows before publication | Conceptual | Can AI-generated knowledge drafts be forced through the normal knowledge approval workflow? |
| **Read-only skill** (GPO documenter) | An agent whose tools are limited to read/summarise actions, with no action that changes records or reaches external systems | Conceptual | Can a skill's available actions be restricted to read-only, and is that enforced or advisory? |
| **Audit log** | Platform logs of AI skill invocations and administrative changes | Conceptual | What is recorded per invocation, does it include prompt/response content, and who can read it? |
| **Prompt-injection handling** | Guardrails or content filters offered around model input and output | Conceptual | What protections exist for untrusted ticket text, and how are they tested? |

Government-cloud note: whether any specific AI feature is available in a government-community or similarly restricted deployment
is something to **confirm with the vendor and the platform administrators**. This repository makes no claim either way.

## 2. Microsoft identity and Microsoft 365 (Entra, Graph, Conditional Access, audit)

| Idea in this repo | Likely analogue | Label | Ask |
|---|---|---|---|
| **A skill's identity** | An **app registration** (and its service principal) that the skill authenticates as, separate from any person | Conceptual | Is each skill given its own registration, with a named owner? |
| **Least-privilege allow-list** | **Microsoft Graph permissions** granted to that app: choose the narrowest read-only permission that does the job, avoid broad read/write permissions, and prefer delegated permissions (acting as the signed-in user) when the user's own access is the right limit | Conceptual | Which exact permissions would the job need, and has an admin reviewed the consent request? |
| **Who may run it** | Role assignments and group-based access to the app, plus **Conditional Access** conditions (who, from where, on what device, with what sign-in strength) | Conceptual | Which Conditional Access policies could apply to a workload or to the people invoking it? Licensing may matter here. |
| **Dry run / approval before change** | A separate approval step, e.g. a change-management process, or privileged-role activation for anything that writes | Conceptual | What gates exist today before a write to the directory or to Microsoft 365? |
| **No write path** (GPO documenter) | Granting **no write permissions at all**, and using exports rather than live access | Conceptual | Can the documenter be fed exports with no connection to the live directory? |
| **Audit log** | **Entra audit and sign-in logs** (including sign-ins by non-human identities), plus Microsoft 365 / Purview audit | Conceptual | Which logs cover app sign-ins and consent grants, how long are they kept, and are they forwarded to a system the operators can't edit? |
| **Secrets** (this repo has none) | Certificates or managed identities rather than client secrets, kept in a managed secret store | Conceptual | What is the approved way to hold a credential for an automation? |

Government-cloud note: Microsoft cloud environments for government customers can differ from the commercial cloud in endpoints
and in which features exist. Confirm per feature in the relevant documentation; nothing here asserts availability.

## 3. A loose link to security frameworks

The ideas here (restrict access to what is needed, separate duties, log security-relevant events, review changes) are the same
ideas that frameworks such as NIST SP 800-53 group under access control and audit/accountability. This project is **inspired by**
those ideas. It has not been assessed against any framework and makes **no claim of compliance** with any standard or authorisation.

## What I would verify first, if given access

1. What a new custom skill or agent can reach by default, and what identity it runs as.
2. Whether field- or table-level restrictions are applied to the data actually sent to the model.
3. Whether AI-generated drafts can be forced through an existing approval workflow, and whether the builder can bypass it.
4. What the logs record per invocation, who can read them, and where they are sent.
5. Which of the features above exist in the specific environments in use (commercial, government-community, high-assurance variants).

## What this mapping does not claim

- That any listed feature exists, is licensed, or behaves as described.
- That I have configured any of this in a real tenant.
- That this repository's code could be dropped into any of those products. It is a teaching model of the controls, not an integration.
