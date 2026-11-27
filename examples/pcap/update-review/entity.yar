rule revoked_update_entity {
    strings:
        $id = "REVOKED-BUILD-042"
    condition:
        filesize == 30 and $id at 12 and #id == 1
}
