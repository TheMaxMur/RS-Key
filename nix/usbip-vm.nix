# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors
#
# A throwaway Linux guest whose only job is to own a USB host controller.
#
# `tools/emu --usbip` speaks the USB/IP protocol, and the thing that turns that
# into `/dev/hidraw*` and a PC/SC reader is the kernel's `vhci_hcd`. A
# GitHub-hosted runner cannot supply it: the module is not in the image and
# hosted runners cannot load one (actions/runner-images#7541), and there is no
# reliable `/dev/kvm` either (community#8305). So the suites that need real USB
# run in here instead, under plain QEMU with software emulation.
#
# The emulator itself stays OUT of this VM, on the host that boots it. It is a
# TCP peer, not a device: QEMU's user-mode networking puts the host at
# `10.0.2.2`, so the guest attaches to it over the network exactly as a second
# machine would. That keeps the guest a fixed appliance — kernel, usbip, pcscd,
# Python — which nothing in a firmware change can invalidate, and keeps the
# emulator's build the same `cargo` one `emu-suites.sh` already does.
#
# Everything is stateless: no disk image, tmpfs root, and the repo arrives over
# 9p, so the tests run against the working tree rather than a copy of it.
{
  nixpkgs,
  system,
  rskPython,
  ccidOverlay,
}:
(nixpkgs.lib.nixosSystem {
  inherit system;
  modules = [
    (nixpkgs + "/nixos/modules/virtualisation/qemu-vm.nix")
    (
      { pkgs, config, ... }:
      {
        # The whole reason this guest exists.
        boot.kernelModules = [ "vhci-hcd" ];

        # pcscd binds by USB id, and the default RS-Key identity (0x1209:0x0001)
        # is not in the stock driver's list — the CCID interface would be skipped
        # silently and every card suite would read as "applet missing". Same
        # overlay `docs/linux.md` tells a user to add.
        nixpkgs.overlays = [ ccidOverlay ];
        services.pcscd.enable = true;

        environment.systemPackages = [
          rskPython
          # Kernel-version-tied: the tool has to match the vhci_hcd it drives.
          config.boot.kernelPackages.usbip
          pkgs.gnupg # the OpenPGP suites shell out to gpg-connect-agent
          pkgs.yubikey-manager # `ykman otp chalresp --touch` arms the slot 77 needs
        ];

        # Boot time is the budget here: this runs under TCG on every PR, so the
        # guest carries nothing it is not about to use.
        documentation.enable = false;
        documentation.nixos.enable = false;
        services.udisks2.enable = false;
        xdg.autostart.enable = false;
        xdg.icons.enable = false;
        xdg.mime.enable = false;
        security.sudo.enable = false;
        networking.firewall.enable = false;

        virtualisation = {
          graphics = false; # serial console on stdout, so a CI log shows the boot
          diskImage = null; # stateless: tmpfs root, nothing to create or clean up
          memorySize = 3072;
          cores = 4; # MTTCG does scale, and a hosted runner has 4
          # `$RSK_REPO` / `$RSK_OUT` are expanded by the run script's shell, not
          # by Nix — which is what lets one built VM serve any checkout.
          sharedDirectories = {
            repo = {
              source = "\"$RSK_REPO\"";
              target = "/repo";
            };
            out = {
              source = "\"$RSK_OUT\"";
              target = "/out";
            };
          };
        };

        # The run itself. A oneshot rather than a login shell so the VM is a
        # command with an exit status: the status file is the result, and the
        # console is the log.
        systemd.services.rsk-usbip-suites = {
          description = "RS-Key: the suites that need a real USB stack";
          wantedBy = [ "multi-user.target" ];
          after = [
            "network-online.target"
            "pcscd.service"
          ];
          wants = [ "network-online.target" ];
          path = [
            rskPython
            config.boot.kernelPackages.usbip
            pkgs.yubikey-manager
            pkgs.kmod
            pkgs.coreutils
            pkgs.gnugrep
            pkgs.bash
          ];
          serviceConfig = {
            Type = "oneshot";
            StandardOutput = "journal+console";
            StandardError = "journal+console";
            # Poweroff outside the unit's own lifetime — calling it from the
            # script deadlocks against systemd waiting on that same unit.
            ExecStopPost = "${pkgs.systemd}/bin/systemctl --no-block poweroff";
          };
          script = ''
            rc=0
            bash /repo/scripts/usbip-guest.sh || rc=$?
            echo "$rc" > /out/status
            sync
          '';
        };

        system.stateVersion = "25.05";
      }
    )
  ];
}).config.system.build.vm
