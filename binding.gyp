{
    "targets": [
        {
            "target_name": "hyperscan",
            "sources": [
                "src/binding.cpp",
                "src/hyperscan_database.cpp"
            ],
            "include_dirs": [
                "<!(node -e \"require('nan')\")",
                "vendor"
            ],
            "link_settings": {
                "libraries": [
                    "-lstdc++",
                    "../lib/libhs.a"
                ]
            },
            "xcode_settings": {
                "MACOSX_DEPLOYMENT_TARGET":"10.9"
            }
        }
    ]
}
