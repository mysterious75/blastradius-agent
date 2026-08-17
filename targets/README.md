# Bounty-Hunting Targets List

Built from the local corpus: **34425 GHSA advisories** → **11131 unique open-source repos**; **14832 HackerOne corpus rows** (program-level).

## How to use

1. **Open-source repos with real CVEs (GHSA)** — clone + `python -m blastradius.agents --target <repo>`; findings are pattern-proven, then verify manually. These are patch-verification + re-audit targets.
2. **HackerOne programs with PUBLIC repos** (GitLab CE, Nextcloud, Rocket.Chat, Mattermost, Node.js, curl, RubyGems, Django, Hyperledger, Kubernetes, Airflow, Concrete CMS...) — scan the public repo, submit findings to their bug-bounty program (authorized only).
3. Always check the program's scope & rules before testing (authorized use only).

## Top 25 GHSA repos by advisory count

| Repo | Advisories | Top severity |
|---|---|---|
| openclaw/openclaw | 2276 | CRITICAL |
| friendsofphp/security-advisories | 1357 | CRITICAL |
| tensorflow/tensorflow | 1167 | CRITICAL |
| moodle/moodle | 907 | CRITICAL |
| xwiki/xwiki-platform | 720 | CRITICAL |
| liferay/liferay-portal | 579 | CRITICAL |
| mattermost/mattermost | 543 | CRITICAL |
| chakra-core/chakracore | 537 | CRITICAL |
| rubysec/ruby-advisory-db | 513 | CRITICAL |
| n8n-io/n8n | 458 | CRITICAL |
| wwbn/avideo | 457 | CRITICAL |
| apache/tomcat | 453 | CRITICAL |
| apache/airflow | 446 | CRITICAL |
| django/django | 445 | CRITICAL |
| jenkinsci/jenkins | 440 | CRITICAL |
| parse-community/parse-server | 438 | CRITICAL |
| open-webui/open-webui | 429 | CRITICAL |
| craftcms/cms | 427 | CRITICAL |
| keycloak/keycloak | 412 | CRITICAL |
| pimcore/pimcore | 397 | CRITICAL |
| magento/magento2 | 392 | CRITICAL |
| go-gitea/gitea | 382 | CRITICAL |
| typo3/typo3 | 376 | CRITICAL |
| flowiseai/flowise | 361 | CRITICAL |
| imagemagick/imagemagick | 415 | HIGH |

## Top HackerOne programs (by upvotes)

| Program | Upvotes |
|---|---|
| Shopify | 2991 |
| PayPal | 2679 |
| Shopify | 1913 |
| HackerOne | 1631 |
| Shopify | 1544 |
| GitLab | 1500 |
| PayPal | 1408 |
| Valve | 1287 |
| X / xAI | 1239 |
| Snapchat | 1185 |
| HackerOne | 1032 |
| Snapchat | 968 |
| GitLab | 942 |
| PayPal | 933 |
| Shopify | 894 |
| Slack | 866 |
| PayPal | 850 |
| Shopify | 830 |
| Semrush | 822 |
| HackerOne | 808 |
| Starbucks | 793 |
| Snapchat | 789 |
| PayPal | 786 |
| Roblox | 780 |
| PlayStation | 777 |
| GitLab | 777 |
| GitLab | 758 |
| PlayStation | 741 |
| Starbucks | 737 |
| GSA Bounty | 698 |
| Starbucks | 686 |
| Glassdoor | 684 |
| PayPal | 683 |
| Razer | 676 |
| HackerOne | 670 |
| Lyft | 653 |
| Uber | 642 |
| Valve | 635 |
| Upserve  | 633 |
| Mail.ru | 631 |
