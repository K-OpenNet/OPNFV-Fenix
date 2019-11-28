# OPNFV-Fenix

This spec describes a Fenix plugin for rolling upgrades in Tacker

## Problem description
For Host upgrade or maintenance, administrator needs to migrate the services running on the host, or provides services through a redundancy model such as ACT-STB. In order to do this, interworking with MANO such as Tacker, which manages the life cycle of VNF, is essential. Fenix project suggested the procedure to work with MANO for maintenance/upgrade [1]. With Fenix, tacker can support maintenance procedure without a service stop. In addition, if VNF provider supports VNF upgrade/maintenance, it also supported in this feature. Therefore, this feature helps the maintenance/upgrade procedure for Host maintenance/upgrade with Fenix. This blueprint is proposed Host maintenance/upgrade mode by leveraging Fenix(rolling infrastructure maintenance, upgrade and scaling).
