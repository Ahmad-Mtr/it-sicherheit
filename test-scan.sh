#!/usr/bin/env bash
set -uo pipefail

# Vollständiger Testlauf für Aufgabenteil B.
# Voraussetzung:
#   1. API starten:
#        cd /pfad/zum/it-sicherheit-repository
#        bun run dev:api
#   2. Dieses Skript in einem zweiten Terminal ausführen.
#
# Das Skript sucht das Repository automatisch im aktuellen Verzeichnis,
# in übergeordneten Verzeichnissen und bis zu vier Ebenen darunter.
#
# Optionale Umgebungsvariablen:
#   PROJECT_ROOT=/pfad/zum/it-sicherheit ./test-scan.sh
#   BASE_URL=http://localhost:3001 ./test-scan.sh
#   SKIP_DB=1 ./test-scan.sh
#   SKIP_TYPECHECK=1 ./test-scan.sh
#   SKIP_GIT=1 ./test-scan.sh
#   SKIP_RATE_LIMIT=1 ./test-scan.sh

BASE_URL="${BASE_URL:-http://localhost:3001}"
BASE_URL="${BASE_URL%/}"
SCAN_URL="${SCAN_URL:-${BASE_URL}/api/scan}"
HTTP_TIMEOUT="${HTTP_TIMEOUT:-60}"

SKIP_DB="${SKIP_DB:-0}"
SKIP_TYPECHECK="${SKIP_TYPECHECK:-0}"
SKIP_GIT="${SKIP_GIT:-0}"
SKIP_RATE_LIMIT="${SKIP_RATE_LIMIT:-0}"

PASS_COUNT=0
FAIL_COUNT=0
SKIP_COUNT=0

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="${PROJECT_ROOT:-}"
LOCAL_PROJECT_AVAILABLE=0

is_project_root() {
  local candidate="$1"

  [[ -f "$candidate/package.json" ]] &&
  [[ -f "$candidate/apps/api/tsconfig.json" ]] &&
  [[ -f "$candidate/apps/api/src/routes/scan.ts" ]] &&
  [[ -f "$candidate/docker-compose.yml" ]]
}

search_ancestors() {
  local current="$1"

  current="$(cd "$current" 2>/dev/null && pwd)" || return 1

  while [[ "$current" != "/" ]]; do
    if is_project_root "$current"; then
      printf '%s\n' "$current"
      return 0
    fi
    current="$(dirname "$current")"
  done

  return 1
}

find_project_root() {
  local found=""
  local base=""
  local scan_file=""

  if [[ -n "$PROJECT_ROOT" ]]; then
    if is_project_root "$PROJECT_ROOT"; then
      cd "$PROJECT_ROOT" && pwd
      return 0
    fi
    return 1
  fi

  for base in "$PWD" "$SCRIPT_DIR"; do
    found="$(search_ancestors "$base" 2>/dev/null || true)"
    if [[ -n "$found" ]]; then
      printf '%s\n' "$found"
      return 0
    fi
  done

  for base in "$PWD" "$SCRIPT_DIR"; do
    scan_file="$(
      find "$base"         -maxdepth 5         -type f         -path '*/apps/api/src/routes/scan.ts'         -not -path '*/node_modules/*'         -print -quit 2>/dev/null
    )"

    if [[ -n "$scan_file" ]]; then
      found="${scan_file%/apps/api/src/routes/scan.ts}"
      if is_project_root "$found"; then
        cd "$found" && pwd
        return 0
      fi
    fi
  done

  return 1
}

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

HTTP_STATUS=""
HTTP_BODY=""

section() {
  printf '\n== %s ==\n' "$1"
}

pass() {
  PASS_COUNT=$((PASS_COUNT + 1))
  printf '[PASS] %s\n' "$1"
}

fail() {
  FAIL_COUNT=$((FAIL_COUNT + 1))
  printf '[FAIL] %s\n' "$1" >&2
}

skip() {
  SKIP_COUNT=$((SKIP_COUNT + 1))
  printf '[SKIP] %s\n' "$1"
}

require_command() {
  local command_name="$1"

  if command -v "$command_name" >/dev/null 2>&1; then
    pass "Programm vorhanden: $command_name"
  else
    fail "Programm fehlt: $command_name"
  fi
}

run_http() {
  local method="$1"
  local url="$2"
  local data="${3-}"
  local body_file="$TMP_DIR/http-body-$(date +%s%N).txt"
  local curl_exit=0

  if [[ -n "$data" ]]; then
    HTTP_STATUS="$(
      curl -sS \
        --max-time "$HTTP_TIMEOUT" \
        -o "$body_file" \
        -w '%{http_code}' \
        -X "$method" \
        "$url" \
        -H 'content-type: application/json' \
        --data-binary "$data"
    )" || curl_exit=$?
  else
    HTTP_STATUS="$(
      curl -sS \
        --max-time "$HTTP_TIMEOUT" \
        -o "$body_file" \
        -w '%{http_code}' \
        -X "$method" \
        "$url"
    )" || curl_exit=$?
  fi

  HTTP_BODY="$(cat "$body_file" 2>/dev/null || true)"

  if (( curl_exit != 0 )); then
    HTTP_STATUS="000"
    return "$curl_exit"
  fi

  return 0
}

run_http_file() {
  local method="$1"
  local url="$2"
  local input_file="$3"
  local body_file="$TMP_DIR/http-body-$(date +%s%N).txt"
  local curl_exit=0

  HTTP_STATUS="$(
    curl -sS \
      --max-time "$HTTP_TIMEOUT" \
      -o "$body_file" \
      -w '%{http_code}' \
      -X "$method" \
      "$url" \
      -H 'content-type: application/json' \
      --data-binary "@$input_file"
  )" || curl_exit=$?

  HTTP_BODY="$(cat "$body_file" 2>/dev/null || true)"

  if (( curl_exit != 0 )); then
    HTTP_STATUS="000"
    return "$curl_exit"
  fi

  return 0
}

is_json() {
  jq -e . >/dev/null 2>&1 <<<"$HTTP_BODY"
}

json_matches() {
  local expression="$1"
  jq -e "$expression" >/dev/null 2>&1 <<<"$HTTP_BODY"
}

show_failed_response() {
  printf '       HTTP-Status: %s\n' "$HTTP_STATUS" >&2
  printf '       Antwort: %s\n' "$(printf '%s' "$HTTP_BODY" | head -c 1200)" >&2
}

expect_status() {
  local expected="$1"
  local description="$2"

  if [[ "$HTTP_STATUS" == "$expected" ]]; then
    pass "$description"
  else
    fail "$description (erwartet HTTP $expected)"
    show_failed_response
  fi
}

expect_validation_status() {
  local description="$1"

  if [[ "$HTTP_STATUS" == "400" || "$HTTP_STATUS" == "422" ]]; then
    pass "$description"
  else
    fail "$description (erwartet HTTP 400 oder 422)"
    show_failed_response
  fi
}

expect_no_internal_details() {
  local description="$1"

  if grep -Eiq \
    'stack trace|node_modules|postgresql|sqlstate|drizzle|at [A-Za-z0-9_.$]+\s*\(' \
    <<<"$HTTP_BODY"; then
    fail "$description"
    show_failed_response
  else
    pass "$description"
  fi
}

check_initial_rate_limit() {
  if [[ "$HTTP_STATUS" == "429" ]]; then
    fail "Scanner war bereits vor dem Test rate-limitiert. API neu starten oder das 60-Sekunden-Fenster ablaufen lassen."
    show_failed_response
    print_summary_and_exit
  fi
}

print_summary_and_exit() {
  section "Ergebnis"
  printf 'Bestanden: %d\n' "$PASS_COUNT"
  printf 'Fehlgeschlagen: %d\n' "$FAIL_COUNT"
  printf 'Übersprungen: %d\n' "$SKIP_COUNT"

  if (( FAIL_COUNT > 0 )); then
    exit 1
  fi

  printf 'Gesamter Testlauf erfolgreich.\n'
  exit 0
}

section "Voraussetzungen"

require_command curl
require_command jq
require_command bun
require_command git

if [[ "$SKIP_DB" != "1" ]]; then
  require_command docker
fi

if (( FAIL_COUNT > 0 )); then
  printf '\nFehlende Programme zuerst installieren.\n' >&2
  print_summary_and_exit
fi

section "Projektstruktur"

RESOLVED_PROJECT_ROOT="$(find_project_root 2>/dev/null || true)"

if [[ -n "$RESOLVED_PROJECT_ROOT" ]]; then
  PROJECT_ROOT="$RESOLVED_PROJECT_ROOT"
  LOCAL_PROJECT_AVAILABLE=1
  cd "$PROJECT_ROOT"
  pass "Repository erkannt: $PROJECT_ROOT"
  pass "Scannerdatei vorhanden: apps/api/src/routes/scan.ts"

  if grep -Eq 'Scanner not implemented yet|TODO\(module-b\)'       apps/api/src/routes/scan.ts; then
    fail "Scanner enthält noch den ursprünglichen TODO-Stub"
  else
    pass "Scanner-TODO wurde entfernt"
  fi

  if grep -q 'matchesVersionRange' apps/api/src/routes/scan.ts; then
    pass "Versionsvergleich verwendet matchesVersionRange"
  else
    fail "matchesVersionRange wird in scan.ts nicht verwendet"
  fi

  if grep -q 'cveCweMap' apps/api/src/routes/scan.ts &&
     grep -q 'potentialImpact' apps/api/src/routes/scan.ts; then
    pass "CWE-Reporting ist in scan.ts enthalten"
  else
    fail "CWE-Reporting ist in scan.ts nicht vollständig erkennbar"
  fi
else
  fail "Repository nicht gefunden"
  printf '       Setze den Pfad explizit, zum Beispiel:\n' >&2
  printf '       PROJECT_ROOT=/mnt/c/Studium/ITS/source/it-sicherheit ./test-scan.sh\n' >&2
fi

section "Statische Prüfungen"

if (( LOCAL_PROJECT_AVAILABLE == 0 )); then
  skip "TypeScript-Prüfung: Repository nicht gefunden"
  skip "Git-Whitespace-Prüfung: Repository nicht gefunden"
else
  if [[ "$SKIP_TYPECHECK" == "1" ]]; then
    skip "TypeScript-Prüfung"
  else
    if bunx tsc -p apps/api/tsconfig.json --noEmit >"$TMP_DIR/tsc.log" 2>&1; then
      pass "TypeScript-Prüfung"
    else
      fail "TypeScript-Prüfung"
      sed -n '1,160p' "$TMP_DIR/tsc.log" >&2
    fi
  fi

  if [[ "$SKIP_GIT" == "1" ]]; then
    skip "Git-Whitespace-Prüfung"
  elif git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
    if git diff --check >"$TMP_DIR/git-diff-check.log" 2>&1; then
      pass "git diff --check"
    else
      fail "git diff --check"
      cat "$TMP_DIR/git-diff-check.log" >&2
    fi
  else
    skip "Git-Whitespace-Prüfung: kein Git-Arbeitsbaum"
  fi
fi

section "Datenbank"

if [[ "$SKIP_DB" == "1" ]]; then
  skip "Datenbankprüfungen"
elif (( LOCAL_PROJECT_AVAILABLE == 0 )); then
  skip "Datenbankprüfungen: Repository nicht gefunden"
else
  POSTGRES_CONTAINER_ID="$(docker compose ps -q postgres 2>/dev/null || true)"

  if [[ -n "$POSTGRES_CONTAINER_ID" ]] &&
     [[ "$(docker inspect -f '{{.State.Running}}' "$POSTGRES_CONTAINER_ID" 2>/dev/null || true)" == "true" ]]; then
    pass "PostgreSQL-Container läuft"
  else
    fail "PostgreSQL-Container läuft nicht"
  fi

  if docker compose exec -T postgres \
      pg_isready -U vuln -d vuln_mgmt >/dev/null 2>&1; then
    pass "PostgreSQL ist erreichbar"
  else
    fail "PostgreSQL ist nicht erreichbar"
  fi

  DB_COUNTS="$(
    docker compose exec -T postgres psql \
      -U vuln \
      -d vuln_mgmt \
      -At \
      -F '|' \
      -c "
        SELECT
          (SELECT COUNT(*) FROM cwe),
          (SELECT COUNT(*) FROM cve),
          (SELECT COUNT(*) FROM cve_cwe_map);
      " 2>/dev/null
  )" || DB_COUNTS=""

  if [[ "$DB_COUNTS" =~ ^([0-9]+)\|([0-9]+)\|([0-9]+)$ ]]; then
    CWE_COUNT="${BASH_REMATCH[1]}"
    CVE_COUNT="${BASH_REMATCH[2]}"
    MAP_COUNT="${BASH_REMATCH[3]}"

    if (( CWE_COUNT >= 20 )); then
      pass "Mindestens 20 CWEs vorhanden ($CWE_COUNT)"
    else
      fail "Zu wenige CWEs vorhanden ($CWE_COUNT)"
    fi

    if (( CVE_COUNT >= 50 )); then
      pass "Mindestens 50 CVEs vorhanden ($CVE_COUNT)"
    else
      fail "Zu wenige CVEs vorhanden ($CVE_COUNT)"
    fi

    if (( MAP_COUNT > 0 )); then
      pass "CVE-CWE-Verknüpfungen vorhanden ($MAP_COUNT)"
    else
      fail "Keine CVE-CWE-Verknüpfungen vorhanden"
    fi
  else
    fail "Datenbankmengen konnten nicht gelesen werden"
  fi

  ANCHOR_COUNT="$(
    docker compose exec -T postgres psql \
      -U vuln \
      -d vuln_mgmt \
      -At \
      -c "
        SELECT COUNT(*)
        FROM cve
        WHERE id IN (
          'CVE-2023-10001',
          'CVE-2023-10002',
          'CVE-2023-10003',
          'CVE-2023-10004'
        );
      " 2>/dev/null
  )" || ANCHOR_COUNT=""

  if [[ "$ANCHOR_COUNT" == "4" ]]; then
    pass "Vier feste Scanner-Test-CVEs vorhanden"
  else
    fail "Feste Scanner-Test-CVEs fehlen (gefunden: ${ANCHOR_COUNT:-unbekannt})"
  fi

  JWT_CWE_COUNT="$(
    docker compose exec -T postgres psql \
      -U vuln \
      -d vuln_mgmt \
      -At \
      -c "
        SELECT COUNT(*)
        FROM cve_cwe_map
        WHERE cve_id = 'CVE-2023-10004'
          AND cwe_id IN ('CWE-287', 'CWE-327');
      " 2>/dev/null
  )" || JWT_CWE_COUNT=""

  if [[ "$JWT_CWE_COUNT" == "2" ]]; then
    pass "CVE-2023-10004 ist mit CWE-287 und CWE-327 verknüpft"
  else
    fail "Erwartete CWE-Verknüpfungen für CVE-2023-10004 fehlen"
  fi
fi

section "API-Basis"

if run_http GET "${BASE_URL}/health"; then
  expect_status "200" "Health-Endpunkt antwortet"
  if is_json && json_matches '.status == "ok"'; then
    pass "Health-Antwort ist korrekt"
  else
    fail "Health-Antwort ist nicht {\"status\":\"ok\"}"
    show_failed_response
  fi
else
  fail "API unter ${BASE_URL} nicht erreichbar"
  show_failed_response
  print_summary_and_exit
fi

run_http GET "${BASE_URL}/docs" || true
expect_status "200" "Swagger-Dokumentation ist erreichbar"

run_http GET "${BASE_URL}/api/cves?product=lodash&version=4.17.20" || true
expect_status "200" "Bestehende CVE-Suche funktioniert"
if is_json && json_matches 'any(.data[]; .id == "CVE-2023-10001")'; then
  pass "CVE-Suche erkennt verwundbares lodash"
else
  fail "CVE-Suche liefert CVE-2023-10001 nicht"
  show_failed_response
fi

run_http GET "${BASE_URL}/api/cves/CVE-2023-10004" || true
expect_status "200" "Einzel-CVE-Endpunkt funktioniert"
if is_json &&
   json_matches '([.cwes[].id] | contains(["CWE-287", "CWE-327"]))'; then
  pass "Einzel-CVE-Endpunkt liefert erwartete CWEs"
else
  fail "Einzel-CVE-Endpunkt liefert CWE-287/CWE-327 nicht"
  show_failed_response
fi

section "Scanner: Maximalinventar, Treffer, Sortierung und Reporting"

if jq -n '
  {
    packages: (
      [
        {name:"jsonwebtoken", version:"8.5.1"},
        {name:"lodash",       version:"4.17.20"},
        {name:"axios",        version:"1.5.0"},
        {name:"express",      version:"4.17.1"}
      ]
      +
      [
        range(4; 1000)
        | {name: ("test-package-" + tostring), version:"1.0.0"}
      ]
    )
  }
' >"$TMP_DIR/inventory-1000.json"; then
  pass "1000er-Testinventar wurde erzeugt"
else
  fail "1000er-Testinventar konnte nicht erzeugt werden"
  printf '{"packages":[]}' >"$TMP_DIR/inventory-1000.json"
fi

INVENTORY_1000_COUNT="$(jq -r '.packages | length' "$TMP_DIR/inventory-1000.json" 2>/dev/null || printf '0')"
if [[ "$INVENTORY_1000_COUNT" == "1000" ]]; then
  pass "1000er-Testinventar enthält exakt 1000 Pakete"
else
  fail "1000er-Testinventar enthält $INVENTORY_1000_COUNT statt 1000 Paketen"
fi

run_http_file POST "$SCAN_URL" "$TMP_DIR/inventory-1000.json" || true
check_initial_rate_limit
expect_status "200" "Inventar mit genau 1000 Paketen wird akzeptiert"

if is_json; then
  pass "Scannerantwort ist gültiges JSON"
else
  fail "Scannerantwort ist kein gültiges JSON"
  show_failed_response
fi

if json_matches '
  .meta.submittedPackages == 1000
  and .meta.scannedPackages == 1000
'; then
  pass "Metadaten für 1000 Pakete sind korrekt"
else
  fail "Metadaten für 1000 Pakete sind fehlerhaft"
  show_failed_response
fi

if json_matches '
  any(.data[]; .id == "CVE-2023-10001")
  and any(.data[]; .id == "CVE-2023-10002")
  and any(.data[]; .id == "CVE-2023-10003")
  and any(.data[]; .id == "CVE-2023-10004")
'; then
  pass "Alle vier festen verwundbaren Pakete werden erkannt"
else
  fail "Mindestens eine feste Test-CVE fehlt"
  show_failed_response
fi

if json_matches '
  [.data[].cvssScore] as $scores
  | $scores == ($scores | sort | reverse)
'; then
  pass "CVSS-Scores sind numerisch absteigend sortiert"
else
  fail "CVSS-Sortierung ist fehlerhaft"
  show_failed_response
fi

if json_matches '
  all(.data[]; (.cwes | type) == "array" and (.cwes | length) > 0)
'; then
  pass "Jede gefundene CVE enthält mindestens eine CWE"
else
  fail "Mindestens eine gefundene CVE enthält keine CWE"
  show_failed_response
fi

if json_matches '
  any(
    .data[];
    .id == "CVE-2023-10004"
    and ([.cwes[].id] | contains(["CWE-287", "CWE-327"]))
  )
'; then
  pass "CVE-2023-10004 enthält CWE-287 und CWE-327"
else
  fail "CWE-Reporting für CVE-2023-10004 ist fehlerhaft"
  show_failed_response
fi

if json_matches '
  any(
    .data[];
    .id == "CVE-2023-10004"
    and any(.matchedPackages[]; .name == "jsonwebtoken" and .version == "8.5.1")
  )
'; then
  pass "matchedPackages enthält das tatsächlich betroffene Paket"
else
  fail "matchedPackages enthält jsonwebtoken 8.5.1 nicht"
  show_failed_response
fi

if json_matches '
  .meta.vulnerablePackages >= 4
  and .meta.vulnerabilitiesFound >= 4
'; then
  pass "Scanner-Metadaten melden die gefundenen Schwachstellen"
else
  fail "Scanner-Metadaten melden zu wenige Treffer"
  show_failed_response
fi

section "Scanner: sichere Version"

run_http POST "$SCAN_URL" \
  '{"packages":[{"name":"lodash","version":"99.0.0"}]}' || true
check_initial_rate_limit
expect_status "200" "Sichere Version wird verarbeitet"

if is_json &&
   json_matches '
     .data == []
     and .meta.submittedPackages == 1
     and .meta.scannedPackages == 1
     and .meta.vulnerablePackages == 0
     and .meta.vulnerabilitiesFound == 0
   '; then
  pass "Sichere lodash-Version erzeugt keine Treffer"
else
  fail "Sichere lodash-Version erzeugt unerwartete Treffer"
  show_failed_response
fi

section "Scanner: Normalisierung und Duplikate"

run_http POST "$SCAN_URL" \
  '{
    "packages":[
      {"name":"lodash","version":"4.17.20"},
      {"name":"LODASH","version":"4.17.20"},
      {"name":" lodash ","version":"4.17.20"},
      {"name":"lodash","version":"99.0.0"}
    ]
  }' || true
check_initial_rate_limit
expect_status "200" "Duplikat-Inventar wird verarbeitet"

if is_json &&
   json_matches '
     .meta.submittedPackages == 4
     and .meta.scannedPackages == 2
     and .meta.vulnerablePackages == 1
     and any(.data[]; .id == "CVE-2023-10001")
   '; then
  pass "Groß-/Kleinschreibung, Leerzeichen und Duplikate werden korrekt behandelt"
else
  fail "Normalisierung oder Duplikatbehandlung ist fehlerhaft"
  show_failed_response
fi

if json_matches '
  all(
    .data[].matchedPackages[];
    .version != "99.0.0"
  )
'; then
  pass "Sichere Parallelversion wird nicht als betroffen gemeldet"
else
  fail "Sichere Parallelversion wird fälschlich als betroffen gemeldet"
  show_failed_response
fi

section "Scanner: Injection-Verhalten"

run_http POST "$SCAN_URL" \
  '{"packages":[{"name":"lodash'\'' OR '\''1'\''='\''1","version":"4.17.20"}]}' || true
check_initial_rate_limit
expect_status "200" "Injection-ähnlicher Produktname verursacht keinen Serverfehler"

if is_json && json_matches '.data == []'; then
  pass "Injection-ähnlicher Produktname liefert keine fremden CVEs"
else
  fail "Injection-Test liefert unerwartete CVEs"
  show_failed_response
fi

expect_no_internal_details "Injection-Antwort enthält keine internen Systemdetails"

section "Scanner: Eingabevalidierung"

run_http POST "$SCAN_URL" '{"packages":[]}' || true
check_initial_rate_limit
expect_validation_status "Leere Paketliste wird abgelehnt"
expect_no_internal_details "Fehlerantwort für leere Liste enthält keine internen Details"

run_http POST "$SCAN_URL" '{"packages":[{"name":"lodash"}]}' || true
check_initial_rate_limit
expect_validation_status "Fehlende Version wird abgelehnt"
expect_no_internal_details "Fehlerantwort für fehlende Version enthält keine internen Details"

run_http POST "$SCAN_URL" \
  '{"packages":[{"name":"","version":"1.0.0"}]}' || true
check_initial_rate_limit
expect_validation_status "Leerer Produktname wird abgelehnt"
expect_no_internal_details "Fehlerantwort für leeren Produktnamen enthält keine internen Details"

run_http POST "$SCAN_URL" \
  '{"packages":[{"name":"lodash","version":""}]}' || true
check_initial_rate_limit
expect_validation_status "Leere Versionsnummer wird abgelehnt"
expect_no_internal_details "Fehlerantwort für leere Version enthält keine internen Details"

jq -n '
  {
    packages: [
      range(0; 1001)
      | {name: ("test-package-" + tostring), version:"1.0.0"}
    ]
  }
' >"$TMP_DIR/inventory-1001.json"

run_http_file POST "$SCAN_URL" "$TMP_DIR/inventory-1001.json" || true
check_initial_rate_limit
expect_validation_status "Inventar mit 1001 Paketen wird abgelehnt"
expect_no_internal_details "Fehlerantwort für 1001 Pakete enthält keine internen Details"

section "Scanner: Rate-Limit"

if [[ "$SKIP_RATE_LIMIT" == "1" ]]; then
  skip "Rate-Limit-Test"
else
  RATE_LIMIT_FOUND=0
  RATE_LIMIT_ATTEMPT=0

  for RATE_LIMIT_ATTEMPT in $(seq 1 15); do
    run_http POST "$SCAN_URL" \
      '{"packages":[{"name":"lodash","version":"99.0.0"}]}' || true

    if [[ "$HTTP_STATUS" == "429" ]]; then
      RATE_LIMIT_FOUND=1
      break
    fi

    if [[ "$HTTP_STATUS" != "200" ]]; then
      fail "Unerwarteter Status während Rate-Limit-Test: HTTP $HTTP_STATUS"
      show_failed_response
      break
    fi
  done

  if (( RATE_LIMIT_FOUND == 1 )); then
    pass "Striktes Rate-Limit antwortet mit HTTP 429"

    if is_json && json_matches '.error == "Too many requests"'; then
      pass "Rate-Limit-Fehlerantwort ist korrekt"
    else
      fail "Rate-Limit-Fehlerantwort ist nicht korrekt"
      show_failed_response
    fi

    printf '       429 trat bei Rate-Limit-Versuch %d auf.\n' "$RATE_LIMIT_ATTEMPT"
  else
    fail "Innerhalb von 15 zusätzlichen Requests trat kein HTTP 429 auf"
  fi
fi

print_summary_and_exit