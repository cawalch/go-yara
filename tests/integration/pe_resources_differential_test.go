package integration

import (
	"testing"

	"github.com/cawalch/go-yara/internal/pefixture"
)

func TestLibyaraPEResources(t *testing.T) {
	libyaraOracle(t)

	sharedLang := &pefixture.ResourceNodeSpec{
		Entries: []pefixture.ResourceEntrySpec{
			{ID: 0x0409, Leaf: &pefixture.ResourceLeafSpec{Payload: []byte("en-us"), CodePage: 1200}},
			{ID: 0x0809, Leaf: &pefixture.ResourceLeafSpec{Payload: []byte("en-uk"), CodePage: 1200}},
		},
	}

	complexRoot := &pefixture.ResourceNodeSpec{
		TimeDateStamp: 0x22334455,
		MajorVersion:  3,
		MinorVersion:  7,
		Entries: []pefixture.ResourceEntrySpec{
			{ID: 16, Leaf: &pefixture.ResourceLeafSpec{Payload: []byte("level1")}},
			{
				ID: 24,
				Subdir: &pefixture.ResourceNodeSpec{
					Entries: []pefixture.ResourceEntrySpec{
						{ID: 1, Leaf: &pefixture.ResourceLeafSpec{Payload: []byte("level2")}},
					},
				},
			},
			{
				Named: true,
				Name:  "CONFIG",
				Subdir: &pefixture.ResourceNodeSpec{
					Entries: []pefixture.ResourceEntrySpec{
						{
							Named: true,
							Name:  "ÜTF",
							Subdir: &pefixture.ResourceNodeSpec{
								Entries: []pefixture.ResourceEntrySpec{
									{Named: true, Name: "LANG", Leaf: &pefixture.ResourceLeafSpec{Payload: []byte("named-leaf")}},
								},
							},
						},
					},
				},
			},
			{
				ID: 10,
				Subdir: &pefixture.ResourceNodeSpec{
					Entries: []pefixture.ResourceEntrySpec{
						{ID: 5, Subdir: sharedLang},
					},
				},
			},
			{
				ID: 3,
				Subdir: &pefixture.ResourceNodeSpec{
					Entries: []pefixture.ResourceEntrySpec{
						{
							ID: 9,
							Subdir: &pefixture.ResourceNodeSpec{
								Entries: []pefixture.ResourceEntrySpec{
									{
										ID: 0x040c,
										Leaf: &pefixture.ResourceLeafSpec{
											HasCustomRVA:  true,
											CustomRVA:     0x99990000,
											HasCustomSize: true,
											CustomSize:    19,
										},
									},
								},
							},
						},
					},
				},
			},
		},
	}

	predicates := []string{
		`defined pe.resource_timestamp`,
		`pe.resource_timestamp == 0`,
		`pe.resource_timestamp == 0x22334455`,
		`defined pe.resource_version.major`,
		`pe.resource_version.major == 3`,
		`pe.resource_version.minor == 7`,
		`defined pe.number_of_resources`,
		`pe.number_of_resources == 0`,
		`pe.number_of_resources == 6`,
		`pe.resources[0].type == pe.RESOURCE_TYPE_VERSION`,
		`defined pe.resources[0].id`,
		`defined pe.resources[0].language`,
		`pe.resources[1].type == pe.RESOURCE_TYPE_MANIFEST`,
		`pe.resources[1].id == 1`,
		`defined pe.resources[1].language`,
		`defined pe.resources[2].type`,
		`defined pe.resources[2].type_string`,
		`pe.resources[2].type_string == "C\x00O\x00N\x00F\x00I\x00G\x00"`,
		`pe.resources[2].name_string == "\xdc\x00T\x00F\x00"`,
		`pe.resources[2].language_string == "L\x00A\x00N\x00G\x00"`,
		`pe.resources[2].length == 10`,
		`pe.resources[2].offset > 0`,
		`pe.resources[3].type == pe.RESOURCE_TYPE_RCDATA`,
		`pe.resources[3].id == 5`,
		`pe.resources[3].language == 0x0409`,
		`pe.resources[4].language == 0x0809`,
		`pe.resources[5].type == pe.RESOURCE_TYPE_ICON`,
		`pe.resources[5].rva == 0x99990000`,
		`defined pe.resources[5].offset`,
		`pe.locale(0x0409) == 1`,
		`pe.locale(0x0809) == 1`,
		`pe.locale(0x040c) == 1`,
		`pe.locale(0x0407) == 0`,
		`pe.locale(-1) == 0`,
		`pe.language(0x09) == 1`,
		`pe.language(0x0c) == 1`,
		`pe.language(0x0409) == 0`,
		`pe.language(-1) == 0`,
		`for any r in pe.resources : (r.type == pe.RESOURCE_TYPE_RCDATA and r.offset > 0)`,
	}

	source := peProbeSource(predicates)
	farRoot := *complexRoot
	farRoot.ExtraTailBytes = 70000
	fixtures := map[string][]byte{
		"non_pe":       []byte("not a portable executable"),
		"empty":        nil,
		"no_dir_pe32":  pefixture.New(false),
		"no_dir_pe64":  pefixture.New(true),
		"empty_pe32":   pefixture.WithResources(pefixture.New(false), false, &pefixture.ResourceNodeSpec{TimeDateStamp: 0x22334455, MajorVersion: 3, MinorVersion: 7}),
		"complex_pe32": pefixture.WithResources(pefixture.New(false), false, complexRoot),
		"complex_pe64": pefixture.WithResources(pefixture.New(true), true, complexRoot),
		"far_payload":  pefixture.WithResources(pefixture.New(true), true, &farRoot),
	}
	for name, data := range fixtures {
		t.Run(name, func(t *testing.T) {
			checkPEPaths(t, source, data)
		})
	}
}
