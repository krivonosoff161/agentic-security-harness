# Runtime Guard provider, copyright, and license boundary

> Source review date: 2026-07-26.
>
> This is an engineering control record, not legal advice.

## Call gate

An external model call is eligible only when all of the following are true:

1. input is self-created synthetic material, public-domain material, or content whose
   exact license grants the needed submission/use rights; a `public` label alone is
   insufficient;
2. no real target, personal data, secret, private code, or raw conversation is present;
3. the provider terms, acceptable-use policy, privacy policy, and exact model license
   have current URLs and SHA-256 records;
4. automated API use and defensive research are allowed;
5. retention/training mode is acceptable and explicitly recorded;
6. region and cross-border posture are accepted;
7. publication status is known;
8. an atomic request/conservative-maximum-cost reservation, bound to a current
   pricing/FX digest with rounding and safety margin, stays within 200 requests and
   150,000 kopecks for this cycle; post-call settlement is required in production;
9. credentials are injected by the existing protected broker and never exposed to an
   agent, command argument, prompt, log, workbook, or Git.

Unknown, stale, blocked, or legally uncertain fields fail closed.

## Current provider decision

| Provider | Engineering status | Rationale |
|---|---|---|
| Alibaba Model Studio | `eligible_for_bounded_review` | This is not blanket legal authorization. Exact current terms, the original model license, input/output rights, region, retention, and the restriction on using Model Studio, its models, or Output to train or develop products or services that compete with Alibaba Cloud or its affiliates must be reviewed per route and model. |
| Yandex AI Studio | `eligible_for_bounded_review` only after exact-route proof | `dataLoggingEnabled=false` is documented specifically for the `FoundationModelsCall` workflow and must not be generalized to REST, SDK, or OpenAI-compatible routes. An account-level logging opt-out is not considered effective until 24 hours after the documented opt-out action; no earlier call is eligible. |
| GigaChat | `hold` | The individual agreement's Freemium mode is limited to personal non-commercial use, while this cycle develops a product. A suitable commercial route and publication interpretation require a separate owner/legal gate. |

No provider was called during foundation implementation.

## Copyright-safe research rules

- Link and paraphrase official sources; do not copy their tables, diagrams, or long text.
- Do not copy vendor code or schemas. Reimplement compatible ideas independently.
- Treat a model answer as a proposal, never a source or originality guarantee.
- Do not publish raw provider output.
- Record every imported artifact separately: type, upstream URL, tag/commit, full
  license, SPDX expression, copyright/NOTICE, commercial and hosted-use rights,
  modification/redistribution rights, patent/trademark clauses, use restrictions, and
  dataset/database rights.
- A missing or ambiguous license means `do not use`.
- "Open weights" does not automatically mean open source.
- Any code import requires a separate SBOM/license-review gate.

## Primary provider sources

Alibaba Cloud:

- [Model Studio Product Terms, section 4.48](https://www.alibabacloud.com/help/en/legal/latest/alibaba-cloud-international-website-product-terms-of-service-v-3-8-0)
- [Model Studio privacy notice](https://www.alibabacloud.com/help/en/model-studio/privacy-notice)
- [Regions and data residency](https://www.alibabacloud.com/help/en/model-studio/regions/)
- [Open-source model terms](https://www.alibabacloud.com/help/en/model-studio/open-source-model-terms)

Yandex:

- [Yandex AI Studio Terms](https://yandex.com/legal/cloud_terms_yandex_ai_studio/en/)
- [Yandex Cloud Acceptable Use Policy](https://yandex.com/legal/cloud_aup/en/)
- [FoundationModelsCall logging control](https://yandex.cloud/en/docs/serverless-integrations/concepts/workflows/yawl/integration/foundationmodelscall)

GigaChat:

- [Agreement for individuals](https://developers.sber.ru/docs/ru/policies/gigachat-agreement/individuals)
- [Permissible-use policy](https://developers.sber.ru/docs/ru/policies/gigachat-agreement/permissible-use-ai)
- [Commercial use](https://developers.sber.ru/docs/ru/gigachat/tariffs/commercial)

License references:

- [SPDX License List](https://spdx.org/licenses/)
- [OSI Open Source Definition](https://opensource.org/osd)
- [OSI Open Source AI Definition 1.0](https://opensource.org/ai/open-source-ai-definition)
- [Creative Commons licenses](https://creativecommons.org/share-your-work/cclicenses/)

## Publication gate

Provider-named benchmark results are not part of this foundation. Before any such
publication, re-review the current agreement, model license, attribution/marking
requirements, confidentiality, and provider-reference rules. Publish only reproducible
aggregates and independently verified conclusions.

Additional named-publication gates:

- Yandex-named communications require the prior agreement described by AI Studio Terms
  clause 3.14;
- GigaChat-named results require written owner/legal/provider clearance for
  confidentiality, commercial use, attribution, and AI marking;
- Alibaba-named results must avoid trademark misuse and any prohibited index of a
  significant portion of Model Studio content, and comply with every applicable
  third-party model license. This project separately prohibits publishing raw provider
  output.
