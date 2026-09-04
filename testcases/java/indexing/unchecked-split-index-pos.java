public class UncheckedSplitIndexPos {
    // a single-line file: no second line -> split("[\\r\\n]+")[1] throws AIOOBE
    public String parseResults(String csvResults) {
        return csvResults.split("[\\r\\n]+")[1];
    }

    public int field(String row) {
        return Integer.parseInt(row.split(",")[2].trim());
    }

    public String fieldChained(String row) {
        return row.split(",")[3].toUpperCase();
    }
}