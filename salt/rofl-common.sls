include:
  - repos

car.build.pkg:
  pkg.installed:
    - pkgs:
      - libconfig-devel
      - rofl-common-devel
      - rofl-common-debuginfo
      - rofl-ofdpa-devel
      - rofl-ofdpa-debuginfo
    - require:
      - pkgrepo: BISDN-priv
      - pkgrepo: toanju-rofl-common
