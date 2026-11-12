# Independent static review worksheet

Give this worksheet and independent-review-packet.json to a reviewer who did not tune the detector. Keep the key and tool results separate until initial annotations are recorded. This omits tool outputs; it is not a double-blind study.

Read source statically. Do not run setup scripts, applications or exploits. Use dangerous, safe_for_specific_flow, or unknown. Identify source, sink, CWE and guard evidence; missing caller/context requires unknown. Patched versions are not automatically safe. Disclose your relationship to detector development and any outputs/patch labels already seen.

| Subject | Source snapshot | Declared focus spans | Judgement | CWE / source / sink / guards | Reviewer / date |
| --- | --- | --- | --- | --- | --- |
| R-198f9216c0 | [Immutable source](https://github.com/mozilla/pollbot/blob/6db74a4fcbff258c7cdf51a6ff0724fc10c485e5/pollbot/middlewares.py) | 61-69 | pending | pending | pending |
| R-1c0f7ade04 | [Immutable source](https://github.com/jupyter/notebook/blob/979e0bd15e794ceb00cc63737fcd5fd9addc4a99/notebook/auth/login.py) | 33-66 | pending | pending | pending |
| R-41855fa531 | [Immutable source](https://github.com/ansible/ansible/blob/cef6296735a0baebcd2f25d967c7bdb770ed6b08/lib/ansible/galaxy/collection.py) | 148-188, 903-942 | pending | pending | pending |
| R-5ebc411ca6 | [Immutable source](https://github.com/langchain-ai/langchain/blob/501cc8311d54a5140cbc5a49d657bc7d70a6f6ab/libs/langchain/langchain/storage/file_system.py) | 38-45, 47-58 | pending | pending | pending |
| R-619d6b6a1a | [Immutable source](https://github.com/ansible/ansible/blob/b2551bb6943eec078066aa3a923e0bb3ed85abe8/lib/ansible/galaxy/collection.py) | 148-198, 913-956 | pending | pending | pending |
| R-61d74905c9 | [Immutable source](https://github.com/mozilla/pollbot/blob/78539afa363b200ef004f40531665826f234eab3/pollbot/middlewares.py) | 61-69 | pending | pending | pending |
| R-8f4771857a | [Immutable source](https://github.com/jupyter/notebook/blob/16cf97cf3cc7bd3bacf939ecd86f2c1cc6944935/notebook/auth/login.py) | 33-63 | pending | pending | pending |
| R-a8cff1068d | [Immutable source](https://github.com/cmusatyalab/opendiamond/blob/398049c187ee644beabab44d6fece82251c1ea56/opendiamond/dataretriever/diamond_store.py) | 123-124 | pending | pending | pending |
| R-cf63693299 | [Immutable source](https://github.com/langchain-ai/langchain/blob/aad3d8bd47d7f5598156ff2bdcc8f736f24a7412/libs/langchain/langchain/storage/file_system.py) | 39-46, 48-67 | pending | pending | pending |
| R-d4c925893f | [Immutable source](https://github.com/langchain-ai/langchain/blob/bf0b3cc0b5ade1fb95a5b1b6fa260e99064c2e22/libs/core/langchain_core/utils/html.py) | 47-103 | pending | pending | pending |
| R-ddb4660f61 | [Immutable source](https://github.com/cmusatyalab/opendiamond/blob/d2f20ffff793f88335f2c0244679d7193295abe2/opendiamond/dataretriever/diamond_store.py) | 122-123 | pending | pending | pending |
| R-f5c931eaa0 | [Immutable source](https://github.com/jupyter/notebook/blob/3cec4bbe21756de9f0c4bccf18cf61d840314d74/notebook/base/handlers.py) | 861-867 | pending | pending | pending |
| R-f63d97192d | [Immutable source](https://github.com/langchain-ai/langchain/blob/817b84de9e2cd9f2e16a11004caea6fa53aefed8/libs/core/langchain_core/utils/html.py) | 47-89 | pending | pending | pending |
| R-faabad787e | [Immutable source](https://github.com/jupyter/notebook/blob/d8308e13803ba1c6e92f129381e615af6c6e00d3/notebook/base/handlers.py) | 861-863 | pending | pending | pending |

Record rationale, required context, exact matching unit and disclosure fields in the JSON packet. Store completed annotations as a new review artifact; preserve the pending template and do not silently rewrite denominators.
