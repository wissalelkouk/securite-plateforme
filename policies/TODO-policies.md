# Policies Kyverno à écrire (TP17 partie 5)

Sur le modèle de `disallow-latest-tag.yaml`, créez un fichier par policy :

| Fichier                         | Règle                                                                     | Indice |
| ------------------------------- | ------------------------------------------------------------------------- | ------ |
| `disallow-privileged.yaml`      | `securityContext.privileged` absent ou `false` pour tous les conteneurs   | ancre `=(securityContext)` |
| `require-run-as-non-root.yaml`  | `runAsNonRoot: true` au niveau du Pod **ou** de chaque conteneur          | `anyPattern` |
| `require-requests-limits.yaml`  | `resources.requests.cpu/memory` et `resources.limits.memory` présents     | valeur `"?*"` |
| `restrict-registries.yaml` *(défi)* | images uniquement depuis `harbor.lab.local/` ou `docker.io/library/` | `"harbor.lab.local/* \| docker.io/library/*"` |

La bibliothèque officielle <https://kyverno.io/policies/> contient des versions de référence : lisez-les **après** avoir écrit les vôtres.
