class mainParams:
    NetworkID = "main"
    DefaultPort = 8333
    StartString = 0xf9beb4d9
    Max_nBits = 0x1d00ffff
    SubsidyHalvingInterval = 210000

    BIP16Exception = 0x00000000000002dc756eebf4f49723ed8d30cc28a5f108eb94b1ba88ac4f9c22
    BIP34Height = 227931
    BIP34Hash = 0x000000000000024b89b42a942fe0d9fea3bb44ab7bd1b19115dd6a759c0808b8

    # 000000000000000004c2b624ed5d7756c508d90fd0da2c7c679febfa6c4735f0
    BIP65Height = 388381

    # 00000000000000000379eaa19dce8c9b722d46ae6a57c2f1a988119488b50931
    BIP66Height = 363725

    PowLimit = 0x00000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffff
    PowTargetTimespan = 14 * 24 * 60 * 60  # two weeks
    PowTargetSpacing = 10 * 60
    RuleChangeActivationThreshold = 1916    # 95% of 2016
    MinerConfirmationWindow = 2016      # PowTargetTimespan / PowTargetSpacing

    GenesisBlockHash = 0x000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f
    GenesisMerkleRoot = 0x4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b
