#!/bin/sh
# =====================================================================
#  NCAE UNIVERSAL AUDIT CROSS-COMPARE SCRIPT
#  Compares two audit outputs by section headers, not REF markers
# =====================================================================

if [ "$#" -ne 2 ]; then
    echo "Usage: $0 <audit-old.txt> <audit-new.txt>"
    exit 1
fi

OLD="$1"
NEW="$2"
TS="$(date +%Y%m%d-%H%M%S)"
OUTFILE="audit-diff-$TS.txt"

echo "=== AUDIT CROSS-COMPARE REPORT ===" | tee "$OUTFILE"
echo "Timestamp: $TS" | tee -a "$OUTFILE"
echo "Old file: $OLD" | tee -a "$OUTFILE"
echo "New file: $NEW" | tee -a "$OUTFILE"
echo "" | tee -a "$OUTFILE"

WORKDIR="$(mktemp -d)"

extract_blocks() {
    FILE="$1"
    OUTDIR="$2"

    awk '
        /^---/ {
            if (section != "") {
                print content > (outdir "/" section)
            }
            section=$0
            gsub(/[^A-Za-z0-9_-]/, "_", section)
            content=""
            next
        }
        {
            content = content $0 "\n"
        }
        END {
            if (section != "") {
                print content > (outdir "/" section)
            }
        }
    ' outdir="$OUTDIR" "$FILE"
}

mkdir "$WORKDIR/old" "$WORKDIR/new"

extract_blocks "$OLD" "$WORKDIR/old"
extract_blocks "$NEW" "$WORKDIR/new"

# Build list of all section names
ls "$WORKDIR/old" "$WORKDIR/new" 2>/dev/null | sort -u > "$WORKDIR/sections"

while read -r SECTION; do
    OLDSEC="$WORKDIR/old/$SECTION"
    NEWSEC="$WORKDIR/new/$SECTION"

    echo "=== SECTION: $SECTION ===" >> "$OUTFILE"

    if [ ! -f "$OLDSEC" ]; then
        echo "Status: ADDED" >> "$OUTFILE"
        echo "--- New Content ---" >> "$OUTFILE"
        cat "$NEWSEC" >> "$OUTFILE"
        echo "" >> "$OUTFILE"
        continue
    fi

    if [ ! -f "$NEWSEC" ]; then
        echo "Status: REMOVED" >> "$OUTFILE"
        echo "--- Old Content ---" >> "$OUTFILE"
        cat "$OLDSEC" >> "$OUTFILE"
        echo "" >> "$OUTFILE"
        continue
    fi

    if diff -q "$OLDSEC" "$NEWSEC" >/dev/null; then
        echo "Status: UNCHANGED" >> "$OUTFILE"
        echo "" >> "$OUTFILE"
        continue
    fi

    echo "Status: CHANGED" >> "$OUTFILE"
    echo "--- Old Content ---" >> "$OUTFILE"
    cat "$OLDSEC" >> "$OUTFILE"
    echo "--- New Content ---" >> "$OUTFILE"
    cat "$NEWSEC" >> "$OUTFILE"
    echo "" >> "$OUTFILE"

done < "$WORKDIR/sections"

echo "=== END OF REPORT ===" | tee -a "$OUTFILE"

rm -rf "$WORKDIR"
