rule Astra_Test_String
{
    meta:
        author = "Astra Development Team"
        description = "Harmless rule used to validate the Astra YARA engine"
        severity = "info"
        category = "testing"

    strings:
        $marker = "ASTRA_YARA_TEST_MARKER" ascii wide

    condition:
        $marker
}
