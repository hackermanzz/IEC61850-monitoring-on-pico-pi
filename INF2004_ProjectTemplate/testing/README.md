# Foundation verification

Run `python3 testing/host/run.py` under WSL/Linux with host GCC and Arm GCC.
The foundation checks production kernel allocation/stack diagnostics and the
shared target ABI. Application subsystem behavior is not yet integrated.

See the project README for target build commands and contributor responsibilities.
Future module commits should add their own real tests and state whether evidence
comes from source inspection, compilation, host execution or physical hardware.
Do not count an unimplemented or disabled module as a passing subsystem test.
