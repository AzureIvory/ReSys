# data

`src/data` is the rule loading and normalization layer for image and WinPE sources.

This package does three jobs:

1. It loads rule files from `rules/core/image-sources` and `rules/core/pe-sources`.
2. It parses several rule formats into one shared model.
3. It sorts, normalizes, and deduplicates the results for downstream install and download code.

If you need to answer any of the following questions, this is the package to read first:

- Where do installable image candidates come from?
- How does a JSON rule file become a `RuleItem`?
- Why did one source override another?
- Why is a renamed JSON file still being loaded?
- How is WinPE source selection different from normal image selection?

## Scope

This package is responsible for:

- Rule directory discovery
- Recursive JSON file collection
- Rule-file parsing
- HTTP or PowerShell-backed remote fetches for dynamic rules
- Text decoding for non-UTF-8 responses
- Converting different rule formats into `RuleItem`
- Converting generic rule items into `WinPEImg`
- Stable ordering and deduplication

This package is not responsible for:

- Actually downloading image files
- Verifying downloaded file hashes
- Mounting, applying, or installing images
- UI presentation
- Persistent caching of parsed rule results

## Files

- [Data.go](/C:/Users/Administrator/Desktop/ReSys/src/data/Data.go): directory scanning, aggregation, normalization, sorting, WinPE conversion and selection
- [parser.go](/C:/Users/Administrator/Desktop/ReSys/src/data/parser.go): single-rule parsing, remote fetch logic, path DSL, text extraction, and rule-item construction

## Public API

### `GetInstallImageItems(system string) ([]RuleItem, error)`

Loads all image-source rules for one target Windows version.

Behavior:

- Normalizes the input system name to one of `7`, `8`, `10`, `11`
- Scans `rules/core/image-sources/<system>`
- Parses every `.json` file recursively
- Skips disabled files
- Normalizes each item
- Deduplicates image candidates
- Sorts them into stable priority order

Accepted input examples:

- `7`
- `win7`
- `windows7`
- `win10-x64`

Only the major system code is used. For example, `win10-x64` still resolves to directory `image-sources/10`.

### `RuleItemFileName(it RuleItem, ln string) string`

Returns the recommended output filename for an image candidate.

Priority order:

1. `RuleItem.FileName`
2. Basename from the download URL
3. `windows_image.<ext>` if the link only exposes an extension
4. `windows_image.iso`

### `GetWinPE() ([]WinPEImg, error)`

Loads and returns all PE candidates from `rules/core/pe-sources`.

Behavior:

- Scans the PE rule tree recursively
- Parses every rule file
- Converts generic `RuleItem` values into `WinPEImg`
- Parses `Offset` into `OffsetStart` and `OffsetEnd`
- Assigns a group name based on the rule path
- Deduplicates and sorts candidates

### `PELnk() (string, float64, []string, error)`

Returns the preferred PE candidate for the current machine architecture.

Selection strategy:

1. Load and sort all PE candidates
2. Prefer an architecture match for `winos.SystemArch()`
3. Fall back to the first sorted candidate when no exact match exists

### `ParseRuleFile(rulePath string) (*RuleParseResult, error)`

Parses one rule file and returns file-level metadata plus its normalized items.

This is the best entry point when you are debugging a single JSON rule.

### `ParseRuleItems(rulePath string) ([]RuleItem, error)`

Convenience wrapper around `ParseRuleFile` when you only need normalized items.

### `ParseRuleWinPEs(rulePath string) ([]WinPEImg, error)`

Convenience wrapper around `ParseRuleItems` that also converts each item into the WinPE-specific structure.

## Core data models

### `RuleItem`

`RuleItem` is the package-wide normalized model. Every rule format converges into this structure.

Important fields:

| Field | Meaning |
| --- | --- |
| `ID` | Item identifier within a rule file |
| `Source` | Logical source name |
| `Rank` | File-level priority, copied onto each item |
| `System` | Target system code such as `7`, `10`, `11` |
| `Name` | Human-readable display name |
| `FileName` | Recommended file name |
| `Description` | Optional description |
| `PublishDate` | Optional release date string |
| `Language` | Language tag such as `zh-cn` or `en-us` |
| `Arch` | Architecture after normalization |
| `Size` | Numeric size value |
| `SizeUnit` | Unit for `Size`, usually `B`, `MB`, or `GB` |
| `Edition` | Optional edition name |
| `Ver` | Optional version string |
| `Index` | Optional image index or sort hint |
| `Hash` | SHA1, SHA256, or MD5 metadata |
| `Link` | Link type and one or more URLs or magnets |
| `Offset` | PE-only style offset text such as `start | end` |

### `RuleHash`

Hash metadata attached to a rule item.

Supported fields:

- `Sha1`
- `Sha256`
- `MD5`

### `RuleLink`

Download metadata attached to a rule item.

Supported fields:

- `Type`
- `Links`

`Type` defaults to `url` when omitted.

### `WinPEImg`

`WinPEImg` is a PE-specific output structure used by PE selection and download code.

Additional fields beyond `RuleItem`:

- `Grp`: group name derived from the rule path
- `OffsetStart`
- `OffsetEnd`

## Directory layout and scan rules

Image rules live under:

```text
rules/core/image-sources/<system>/
```

PE rules live under:

```text
rules/core/pe-sources/
```

Directory scanning rules:

- Scanning is recursive
- Any file with extension `.json` is included
- Files are sorted by path before parsing
- Disabled files are skipped after parsing
- A file name is not a lookup key by itself

That last point matters: the package does not ask for `win7-en-us1.json` by name. It scans the directory and parses all JSON files it finds.

## Rule file lifecycle

The package processes rule files in two layers.

### Layer 1: directory aggregation

`loadRules` in [Data.go](/C:/Users/Administrator/Desktop/ReSys/src/data/Data.go:321) is responsible for:

- Walking a directory tree
- Parsing each file with `ParseRuleFile`
- Skipping files where `Enabled == false`
- Skipping files that produce zero items
- Sorting aggregated sources by `Rank`, `Source`, and path

This layer does not know the details of a specific rule format.

### Layer 2: single-file parsing

`ParseRuleFile` in [parser.go](/C:/Users/Administrator/Desktop/ReSys/src/data/parser.go:133) handles one JSON file.

Defaults applied before parsing:

- `method`: defaults to `GET`
- `SizeUnit`: defaults to `B`
- `timeout`: defaults to `8000` milliseconds
- `Enabled`: defaults to `true`
- `Source`: defaults to the file basename when omitted

Mode selection is:

1. If `parser` is set, use the named parser mode
2. Else if `items` is present, use direct item mode
3. Else if `rules` is present, use dynamic JSON mapping mode
4. Otherwise return an error

## Supported rule modes

The package currently supports three rule modes.

## 1. `items` mode

This is the simplest rule format. The JSON file already contains concrete item objects.

Use this when:

- The source is static
- No remote request is needed
- You want maximum readability

Minimal example:

```json
{
  "Source": "win7-en-us1",
  "Rank": 9,
  "Enabled": true,
  "SizeUnit": "GB",
  "items": {
    "Windows 7 Ultimate": {
      "System": "7",
      "Name": "Windows 7 Ultimate with Service Pack 1 (x64)",
      "FileName": "win7sp1_x64_en-us.iso",
      "Language": "en-us",
      "Arch": "64",
      "Size": "5.47",
      "hash": {
        "SHA1": "7CC76B0015220DE956328FB934D61B710A94293D"
      },
      "link": {
        "type": "bt",
        "link1": "magnet:?xt=urn:btih:..."
      }
    }
  }
}
```

Implementation notes:

- Each key under `items` becomes the default `ID`
- Each value must be a JSON object
- `System` falls back to file-level `system` when omitted
- `Description` accepts alias `Desc`
- `PublishDate` accepts alias `Date`
- `Ver` accepts alias `ver` or `Ver`

## 2. `rules` mode

This mode fetches remote JSON and maps fields into `RuleItem`.

Use this when:

- The upstream source exposes structured JSON
- The item list changes over time
- You need a remote-driven source without writing custom Go code

Minimal example:

```json
{
  "Source": "example-api",
  "Rank": 8,
  "system": "10",
  "method": "get",
  "url": {
    "primary": "https://example.test/images.json"
  },
  "SizeUnit": "GB",
  "rules": {
    "Name": "$.data.items[number].title",
    "FileName": "$.data.items[number].file_name",
    "Language": "$.data.items[number].lang",
    "Arch": "$.data.items[number].arch",
    "Size": "$.data.items[number].size",
    "hash": {
      "Sha1": "$.data.items[number].sha1"
    },
    "link": {
      "type": "url",
      "link1": "$.data.items[number].url"
    }
  }
}
```

How it works:

1. Read and sort the `url` map values
2. Fetch each remote JSON document
3. Infer the iteration container from the first dynamic path that contains `[number]` or `[key]`
4. Build one iteration context per array item or object entry
5. Resolve each configured field
6. Deduplicate items produced by multiple URLs

Important constraint:

- There is no wildcard syntax
- Iteration is driven by `[number]` and `[key]`
- If no dynamic path is found, the root object is treated as one single item

## 3. `parser = "section_kv_group_v1"`

This mode fetches text, splits it into sections, groups numbered key/value fields, and then builds items.

Use this when:

- The upstream source is plain text, not JSON
- The data is arranged as key/value blocks
- Related values are encoded as numbered fields such as `PE1Name`, `PE1Url`, `PE2Name`

High-level flow:

1. Fetch remote text
2. Decode UTF-8 or GBK
3. Split the content into `[Section]` blocks
4. Parse loose `Key=Value` pairs inside each section
5. Group numbered keys with `group.key_regex`
6. Build one `RuleItem` per grouped entry
7. Optionally extract extra fields with regex

Minimal example:

```json
{
  "Source": "easyrc-pe",
  "Rank": 9,
  "parser": "section_kv_group_v1",
  "system": "10",
  "url": {
    "primary": "https://example.test/pe.txt"
  },
  "SizeUnit": "MB",
  "sections": {
    "WinPE": {
      "Arch": "64",
      "Language": "zh-cn"
    }
  },
  "group": {
    "key_regex": "^PE(?P<num>[0-9]+)(?P<field>Name|Url|Url2|MS)$",
    "required_fields": ["Name", "Url"]
  },
  "field_map": {
    "Name": "Name",
    "Link1": "Url",
    "Link2": "Url2",
    "Description": "MS"
  },
  "extract": {
    "Ver": {
      "from": "Name",
      "regex": "([0-9]+(?:\\.[0-9]+)*)"
    }
  }
}
```

Default `field_map` values are:

| Normalized field | Default source field |
| --- | --- |
| `Name` | `Name` |
| `Link1` | `Url` |
| `Link2` | `Url2` |
| `Meta` | `MS` |

## Root-level rule fields

These root fields are accepted by all rule modes where they make sense.

| Field | Required | Meaning |
| --- | --- | --- |
| `Source` | No | Stable logical source name |
| `Rank` | No | Higher values win |
| `Enabled` | No | Whether this rule participates in directory aggregation |
| `system` | No | Default system code for items |
| `method` | No | HTTP method, usually `get` or `post` |
| `headers` | No | Extra HTTP headers |
| `data` | No | JSON request body for `POST` |
| `SizeUnit` | No | Default size unit for generated items |
| `timeout` | No | Request timeout in milliseconds |

Rules-mode specific fields:

- `url`
- `rules`

Section parser specific fields:

- `parser`
- `sections`
- `group`
- `field_map`
- `extract`

Items-mode specific field:

- `items`

## `Source`, `Rank`, and `Enabled`

These three metadata fields control most aggregation behavior.

### `Source`

`Source` is the logical source name attached to the file and copied onto its items.

Rules:

- If present, it is used as-is
- If omitted, the package uses the JSON filename without extension
- The parsed `RuleItem.Source` value comes from file-level metadata

Recommendation:

- Treat `Source` as a stable identifier
- Do not rely on the filename as the identity unless you intentionally want that coupling

### `Rank`

`Rank` is the source priority. Higher values sort first.

The package uses `Rank` in:

- Source ordering during aggregation
- Image candidate ordering
- PE candidate ordering
- Tie-breaking during deduplication, because higher-ranked sources are seen first

### `Enabled`

`Enabled` controls whether a rule file participates in directory aggregation.

Behavior:

- Missing value means enabled
- `false` means the file still parses individually, but `loadRules` skips it during directory aggregation

## Path DSL used by `rules` mode

This package does not use JSONPath. It has its own small path language.

Supported syntax:

| Syntax | Meaning |
| --- | --- |
| `$` | Root object |
| `$.field` | Object field |
| `$.field.sub` | Nested field |
| `$.list[0]` | Array index |
| `$.items[number]` | Current iterated item |
| `$.items[key]` | Current iterated object key |

Examples:

| Expression | Result |
| --- | --- |
| `$.data.items[number].title` | Current item title |
| `$.data.items[number].url` | Current item URL |
| `$.data.catalog[key].sha1` | SHA1 for the current object entry |

Important semantics:

- `[number]` means "current iterated value", not strictly an integer placeholder
- `[key]` is only meaningful when iterating an object
- Any dynamic path resolution failure returns an empty value instead of a hard error
- The container path itself must resolve successfully, otherwise parsing fails

## HTTP fetch behavior

Dynamic rules can fetch remote data.

Request behavior:

- Supports `GET` and `POST`
- Serializes `data` as JSON for `POST`
- Applies custom `headers`
- Injects a default browser-like `User-Agent` when absent
- Injects `Accept: */*` when absent
- Uses `timeout` in milliseconds
- Retries failed HTTP requests once

Validation-cookie behavior:

- The package scans the first response for `document.cookie="..."`
- If found, it extracts the first cookie pair
- It retries the request with that cookie attached

Windows fallback behavior:

- If the native Go HTTP request fails, the package tries a PowerShell `Invoke-WebRequest` fallback
- This fallback is only available on Windows

## Text decoding behavior

Text-based parser modes call `decodeRuleText`.

Behavior:

- If the response is valid UTF-8, use it directly
- Otherwise try GBK decoding
- If GBK decoding fails, fall back to the raw bytes

This exists because some upstream rule sources return legacy Chinese encodings.

## Normalization rules

After parsing, the package normalizes several fields.

### System normalization

User input for image loading is normalized by `normalizeSystemCode`.

Accepted final values:

- `7`
- `8`
- `10`
- `11`

Anything else returns an error.

### Architecture normalization

`normalizeArch` maps common aliases to canonical values.

Mappings:

- `arm64`, `aarch64` -> `arm64`
- `x64`, `amd64`, `64` -> `64`
- `x86`, `i386`, `32`, `86` -> `32`

### Link normalization

- Empty links are removed
- Duplicate links are removed
- Link order is preserved by first occurrence
- Missing `link.type` becomes `url`

## Sorting and deduplication

Understanding sorting is important because the package keeps the first candidate it sees for a dedup key.

### Source ordering

Rule files are ordered by:

1. Higher `Rank`
2. Lexicographically smaller `Source`
3. Rule path

### Image-item dedup key

Image candidates are deduplicated by:

- Normalized `Arch`
- `Link.Type`
- `Hash.Sha1`
- `FileName`
- `Index`
- All link values joined in order

Two items with the same values above are considered the same image candidate.

### Image-item final sort order

Image candidates are sorted by:

1. Higher `Rank`
2. Lexicographically smaller `Link.Type`
3. Higher `Index`
4. Lexicographically smaller `FileName`
5. Lexicographically smaller `Source`
6. Stable item key

### PE dedup key

PE candidates are deduplicated by:

- `Name`
- Normalized `Arch`
- Link list
- `MD5`
- `OffsetStart`
- `OffsetEnd`

### PE final sort order

PE candidates are sorted by:

1. Higher `Rank`
2. Higher parsed numeric version from `Ver` or `Name`
3. Lexicographically smaller `Name`
4. Lexicographically smaller `Source`
5. Stable PE key

## WinPE-specific behavior

PE aggregation has a few extra rules that normal image aggregation does not.

### Group derivation

`peGroupFromRule` derives a group label from the rule path.

Examples:

- `pe-sources/direct/a.json` -> `direct`
- `pe-sources/easyrc.json` -> `easyrc`

### Offset parsing

`Offset` is expected in the form:

```text
start | end
```

Behavior:

- Missing or partial offsets are ignored
- Invalid numbers return an error during PE conversion

## Error handling model

The package is intentionally tolerant at the directory level.

### Directory-level behavior

When scanning a directory:

- One bad rule file does not immediately abort the whole scan
- Errors are accumulated
- Successfully parsed files are still used
- If nothing usable remains, an aggregated error is returned

### Single-file behavior

When parsing one rule file:

- Invalid JSON is fatal
- Unknown parser names are fatal
- Missing required rule-mode pieces are fatal
- Missing dynamic field values usually become empty strings, not errors

This tradeoff keeps remote-rule parsing resilient while still surfacing malformed rule definitions.

## Practical guidance for rule authors

Prefer `items` mode when the source is static.

Use `rules` mode when:

- The upstream API is JSON
- The schema is stable
- You do not need custom Go logic

Use `section_kv_group_v1` when:

- The upstream source is legacy text
- The data is grouped by numbered fields

Recommendations:

- Always set an explicit `Source`
- Always set an explicit `Rank`
- Keep one language family per file when possible
- Use stable filenames and source identifiers
- Normalize hash field names to `Sha1`, `Sha256`, `MD5` when authoring new rules
- Avoid mixing unrelated sources into one file

## Debugging tips

If a rule file is not showing up in aggregated results, check these first:

1. The file is under the correct directory tree.
2. The extension is still `.json`.
3. `Enabled` is not `false`.
4. The file produced at least one item with a filename or link.
5. Another higher-ranked rule did not already win the same dedup key.

If a `rules`-mode file returns zero items, check:

1. The container path inferred from `[number]` or `[key]` actually exists.
2. The remote JSON field names still match your expressions.
3. The resolved links are non-empty.

If a PE rule is ignored, check:

1. The rule generated at least one link.
2. `Offset` is either empty or parseable as `start | end`.
3. A duplicate PE candidate was not already accepted earlier.

## Maintenance notes

The package is deliberately data-driven. Before adding a new custom parser in Go, verify that the source cannot be represented with:

- `items`
- `rules`
- `section_kv_group_v1`

Only add a new parser mode when the source shape is fundamentally different and cannot be modeled with the existing DSL plus extraction steps.

## Related code

- [src/install/download.go](/C:/Users/Administrator/Desktop/ReSys/src/install/download.go): consumes `RuleItem` image sources
- [rules/core/readme.md](/C:/Users/Administrator/Desktop/ReSys/rules/core/readme.md): repository-level rule authoring notes

## Quick reference

### Which function should I call?

| Need | Function |
| --- | --- |
| Parse one rule file | `ParseRuleFile` |
| Get only normalized items from one file | `ParseRuleItems` |
| Convert one rule file to PE objects | `ParseRuleWinPEs` |
| Load all install-image candidates for a target system | `GetInstallImageItems` |
| Load all PE candidates | `GetWinPE` |
| Pick the preferred PE for the current machine | `PELnk` |

### Which rule mode should I use?

| Situation | Recommended mode |
| --- | --- |
| Static list of URLs or magnets | `items` |
| Remote JSON API | `rules` |
| Legacy text config or INI-like source | `section_kv_group_v1` |
