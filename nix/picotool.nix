# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors
{ pkgs }:
pkgs.picotool.overrideAttrs (old: {
  patches = (old.patches or [ ]) ++ [ ./picotool-ecdsa.patch ];
  postPatch = (old.postPatch or "") + ''
    cp ${./picotool-signature-tests.c} rsk-signature-tests.c
    cat >> CMakeLists.txt <<'EOF'
    add_executable(rsk-signature-tests rsk-signature-tests.c)
    target_link_libraries(rsk-signature-tests PRIVATE bintool)
    EOF
  '';
  postBuild = (old.postBuild or "") + ''
    ./rsk-signature-tests
  '';
})
