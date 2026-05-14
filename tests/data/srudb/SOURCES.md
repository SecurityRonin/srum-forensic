# SRUDB Test Fixtures — Provenance

Real SRUDB.dat files from independent third-party sources.
These exist specifically to catch parser bugs that synthetic fixtures (built by us)
cannot detect — a doer-checker violation where both the fixture builder and the
parser encode the same incorrect assumption.

All files verified as valid ESE databases (magic `0x89ABCDEF` at offset 4).

## Summary Table

| Filename | Size | Source | License | Windows version | Notes |
|---|---|---|---|---|---|
| `chainsaw_SRUDB.dat` | 1.75 MB | WithSecureLabs/chainsaw | Apache-2.0 | Windows 10 (APTSimulatorVM) | Paired with SOFTWARE hive + expected JSON output for ground-truth validation |
| `plaso_SRUDB.dat` | 7.5 MB | log2timeline/plaso | Apache-2.0 | Unknown (likely Win10) | Exercises real-world IdBlob edge case in SruDbIdMapTable (plaso issue #2134) |
| `museum_belkasoftctf_win10_SRUDB.dat` | 3.1 MB | AndrewRathbun/DFIRArtifactMuseum | MIT | Windows 10 | From Belkasoft CTF "Insider Threat" challenge; clean (ESE-repaired) copy |
| `museum_rathbunvm_win10_SRUDB.dat` | 768 KB | AndrewRathbun/DFIRArtifactMuseum | MIT | Windows 10 (RathbunVM) | Clean (ESE-repaired) copy from Andrew Rathbun's personal Win10 VM |
| `museum_rathbunvm_win11_SRUDB.dat` | 2.4 MB | AndrewRathbun/DFIRArtifactMuseum | MIT | Windows 11 (RathbunVM) | Clean (ESE-repaired) copy from Andrew Rathbun's personal Win11 VM |
| `museum_aptvm_server2022_clean_SRUDB.dat` | 192 KB | AndrewRathbun/DFIRArtifactMuseum | MIT | Windows Server 2022 (APTSimulatorVM) | Clean baseline before APTSimulator run |
| `museum_aptvm_server2022_1daylater_SRUDB.dat` | 640 KB | AndrewRathbun/DFIRArtifactMuseum | MIT | Windows Server 2022 (APTSimulatorVM) | Captured 1 day after APTSimulator run; shows post-attack SRUM entries |

## Files

### chainsaw_SRUDB.dat
- **Origin**: WithSecure Labs / Chainsaw — SRUM analysis test suite
- **Source URL**: https://raw.githubusercontent.com/WithSecureLabs/chainsaw/master/tests/srum/SRUDB.dat
- **Size**: 1,835,008 bytes (448 pages × 4096)
- **SHA-256**: `fb3b913c8a94fae7d73f6d5641af9dd1a0040133744e07927082214a436d5c00`
- **License**: Apache-2.0 (Chainsaw repo)
- **Notes**: Comes with a paired SOFTWARE hive and expected JSON output in the
  Chainsaw repo, making it suitable for ground-truth validation.

### plaso_SRUDB.dat
- **Origin**: log2timeline / Plaso — SRUM parser regression test
- **Source URL**: https://raw.githubusercontent.com/log2timeline/plaso/main/test_data/SRUDB.dat
- **Size**: 7,864,320 bytes (1920 pages × 4096)
- **SHA-256**: `6536ae6bb5b91f6f8f37a4af26f6cfaecc8a1f745370bfba83af7ebae6694e3e`
- **License**: Apache-2.0 (Plaso repo)
- **Notes**: Plaso issue #2134 noted `IdBlob value missing from SruDbIdMapTable` —
  the file exercises a known real-world edge case in the ID map table.

### museum_belkasoftctf_win10_SRUDB.dat
- **Origin**: AndrewRathbun/DFIRArtifactMuseum — Belkasoft CTF "Insider Threat" challenge
- **Source URL**: https://github.com/AndrewRathbun/DFIRArtifactMuseum/tree/main/Windows/SRUM/Win10/BelkasoftCTF_InsiderThreat/Clean
- **Size**: 3,211,264 bytes (784 pages × 4096)
- **SHA-256**: `b2c06003c6763b1f15272381f5d3f077264168975ee0aa8d08bac92e1c99e796`
- **License**: MIT (DFIRArtifactMuseum repo)
- **Windows version**: Windows 10
- **Notes**: Clean (ESE-repaired) copy. Originally from the Belkasoft CTF "Insider Threat"
  challenge — real artifact from a CTF forensics scenario, good for testing typical user
  activity patterns.

### museum_rathbunvm_win10_SRUDB.dat
- **Origin**: AndrewRathbun/DFIRArtifactMuseum — Andrew Rathbun's personal Win10 VM
- **Source URL**: https://github.com/AndrewRathbun/DFIRArtifactMuseum/tree/main/Windows/SRUM/Win10/RathbunVM/Clean
- **Size**: 786,432 bytes (192 pages × 4096)
- **SHA-256**: `f0ce646fee265c8c438459fc3bcb616e084c875389a6189d2945be4a52e1602c`
- **License**: MIT (DFIRArtifactMuseum repo)
- **Windows version**: Windows 10
- **Notes**: Clean (ESE-repaired) copy from a real personal Windows 10 machine.
  Smallest of the collection — likely a relatively fresh VM with limited history.

### museum_rathbunvm_win11_SRUDB.dat
- **Origin**: AndrewRathbun/DFIRArtifactMuseum — Andrew Rathbun's personal Win11 VM
- **Source URL**: https://github.com/AndrewRathbun/DFIRArtifactMuseum/tree/main/Windows/SRUM/Win11/RathbunVM/Clean
- **Size**: 2,490,368 bytes (608 pages × 4096)
- **SHA-256**: `f2aeeafe6843aefba35756ffee0eea128b97ec985f852a6c074267a71ceb1696`
- **License**: MIT (DFIRArtifactMuseum repo)
- **Windows version**: Windows 11
- **Notes**: Clean (ESE-repaired) copy from a real personal Windows 11 machine.
  Only Windows 11 sample in the collection — useful for catching Win11-specific schema differences.

### museum_aptvm_server2022_clean_SRUDB.dat
- **Origin**: AndrewRathbun/DFIRArtifactMuseum — APTSimulatorVM on Windows Server 2022
- **Source URL**: https://github.com/AndrewRathbun/DFIRArtifactMuseum/tree/main/Windows/SRUM/Server2022/APTSimulatorVM
- **Size**: 196,608 bytes (48 pages × 4096)
- **SHA-256**: `b36aafc14c3ae135a857a7b6c63e41c2845686721eb15ff50dfb3ca32c842675`
- **License**: MIT (DFIRArtifactMuseum repo)
- **Windows version**: Windows Server 2022
- **Notes**: Baseline clean SRUM snapshot before APTSimulator tool was run.
  Captured 2023-10-18. Only Server 2022 sample; useful for testing server-class SRUM behavior.

### museum_aptvm_server2022_1daylater_SRUDB.dat
- **Origin**: AndrewRathbun/DFIRArtifactMuseum — APTSimulatorVM on Windows Server 2022
- **Source URL**: https://github.com/AndrewRathbun/DFIRArtifactMuseum/tree/main/Windows/SRUM/Server2022/APTSimulatorVM
- **Size**: 655,360 bytes (160 pages × 4096)
- **SHA-256**: `eb683ffcea831e6e81e28df9c98f8d441b5143fa23c0092c1286c0b911370349`
- **License**: MIT (DFIRArtifactMuseum repo)
- **Windows version**: Windows Server 2022
- **Notes**: Captured 1 day after running APTSimulator (a red-team simulation tool).
  Pair with the `_clean` variant to diff pre/post attack SRUM entries.
  Captured 2023-10-18 ~21:46 local time.

## Re-downloading

```bash
# Original fixtures
curl -fsSL -o tests/data/srudb/chainsaw_SRUDB.dat \
  'https://raw.githubusercontent.com/WithSecureLabs/chainsaw/master/tests/srum/SRUDB.dat'

curl -fsSL -o tests/data/srudb/plaso_SRUDB.dat \
  'https://raw.githubusercontent.com/log2timeline/plaso/main/test_data/SRUDB.dat'

# DFIRArtifactMuseum fixtures (via GitHub blob API — files are base64-encoded in API response)
# See: https://github.com/AndrewRathbun/DFIRArtifactMuseum/tree/main/Windows/SRUM
```

Verify with:
```bash
shasum -a 256 tests/data/srudb/*.dat
```
