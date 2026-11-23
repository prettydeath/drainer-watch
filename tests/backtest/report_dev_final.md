# Backtest report: dev (final)

Generated 2026-11-23T11:15:17Z. Mode: BLIND (seeds disabled for detection; family library = dev targets only, own component excluded); source: eth_getBlockReceipts + full blocks; window +/-1 blocks around each incident.

## Summary

| metric | value | baseline |
|---|---|---|
| incidents | 114 | 114 |
| distinct seeds | 45 | 45 |
| recall T1/T2 (incidents) | 21.1% | 0.0% |
| recall any tier (incidents) | 72.8% | 0.0% |
| seeds with >=1 T1/T2 detection | 6 | 0 |
| TP flagged addresses (T1/T2) | 6 | 0 |
| other T1/T2 flagged addresses (FP candidates) | 6 | 6 |
|   of which ScamSniffer/wa-scam/incident addr (likely TP) | 0 | 0 |
| precision strict (TP / all T1-T2 flagged) | 50.0% | 0.0% |
| precision adjusted (likely-TP FPs counted as TP) | 50.0% | 0.0% |
| payout-role incidents | 0 | 0 |
|   seed recovered as payout wallet | 0 | 0 |
| detected incidents with payout wallets | 0 | 0 |

## Recall per detector (incidents whose flagged target carries the label)

| detector | any tier | T1/T2 | baseline any / T1-T2 |
|---|---|---|---|
| eoa_spender_pull | 83 | 24 | 0 / 0 |
| eoa_spender_multi | 24 | 24 | 0 / 0 |

## Recall by drain pattern / seed role (detected T1-T2 / total)

| group | value | detected / total |
|---|---|---|
| pattern | eoa_transferFrom | 24 / 96 |
| pattern | pull_via_contract | 0 / 15 |
| pattern | via_allowlisted | 0 / 3 |
| seed role | drainer_contract | 0 / 14 |
| seed role | operator | 24 / 100 |

## Incidents

| block | ts | tx | seed | role | pattern | tx.to | flagged | tier | labels | payouts |
|---|---|---|---|---|---|---|---|---|---|---|
| 22153192 | 2025-03-29T14:35:23Z | 0x75fd364a4ae5d47f7a451f540d099ea067f5119445608a5e690c07f50938c60c | 0x0000098a312e1244f313f83cac319603a97f4582 | operator | eoa_transferFrom | 0xc011a73ee8576fb46f5e1c5751ca3b9fe0af2a6f |  | - |  |  |
| 22153210 | 2025-03-29T14:38:59Z | 0x5cd8f929ad8af6e1e9a388b37340900a3e9db61f1eeafcf3a40cf737deb0b01d | 0x0000098a312e1244f313f83cac319603a97f4582 | operator | eoa_transferFrom | 0xae7ab96520de3a18e5e111b5eaab095312d7fe84 |  | - |  |  |
| 22198140 | 2025-04-04T21:07:23Z | 0x671c324838f9f6b63211e044e5a12a055a988d39538b86155a6420aa64a7b720 | 0x0000098a312e1244f313f83cac319603a97f4582 | operator | eoa_transferFrom | 0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48 |  | - |  |  |
| 23317034 | 2025-09-08T07:58:59Z | 0x8d8d38a7ea0629f62342343e062653dc1196271ff840c0ffc9745996dd864e01 | 0x0000098a312e1244f313f83cac319603a97f4582 | operator | eoa_transferFrom | 0x4e3fbd56cd56c3e72c1403e103b45db9da5b9d2b |  | - |  |  |
| 24262784 | 2026-01-18T16:17:59Z | 0x9e7cc75f40f32102c69713a785d54c0d7ff2398761a5cb5ff4fdb3a9546f3170 | 0x03499474a491ef05127d8087a227089361ba7303 | operator | eoa_transferFrom | 0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48 |  | - |  |  |
| 25057430 | 2026-05-09T12:09:35Z | 0xe08bda88dd9c4d290675a1fea79fc3082c21128b7672e53ad2069488f3e6faf9 | 0x03499474a491ef05127d8087a227089361ba7303 | operator | eoa_transferFrom | 0xdac17f958d2ee523a2206206994597c13d831ec7 |  | - |  |  |
| 25057431 | 2026-05-09T12:09:47Z | 0x17d78ddc29e95022847b739863e97510ab9dc8a008b08fcc426122570e687c2c | 0x03499474a491ef05127d8087a227089361ba7303 | operator | eoa_transferFrom | 0xdac17f958d2ee523a2206206994597c13d831ec7 |  | - |  |  |
| 25080493 | 2026-05-12T17:20:47Z | 0xbeccc100b22be12e55e1acbfd60938abfec4df91d74e7859c06d0c416e4ee763 | 0x03499474a491ef05127d8087a227089361ba7303 | operator | eoa_transferFrom | 0xdac17f958d2ee523a2206206994597c13d831ec7 |  | - |  |  |
| 22762633 | 2025-06-22T21:22:47Z | 0x4d9ec86a37eb288126651068c305a05068763eee5be1e75df40549aeaa096fe5 | 0x04914e7f178a1f3717d5afabfc2103255bcc0a5f | operator | eoa_transferFrom | 0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48 | 0x04914e7f178a1f3717d5afabfc2103255bcc0a5f | T3 | eoa_spender_pull, wa_scam |  |
| 22762777 | 2025-06-22T21:51:47Z | 0x076e6e5c9d935c880c348c6bcb85bed8e0a113e813a40dd799e6a78151239bd3 | 0x04914e7f178a1f3717d5afabfc2103255bcc0a5f | operator | eoa_transferFrom | 0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48 | 0x04914e7f178a1f3717d5afabfc2103255bcc0a5f | T3 | eoa_spender_pull, wa_scam |  |
| 26311784 | 2026-10-31T09:15:11Z | 0xc6ca2b03983b2bfc6426cb87ac39f7c7d98147a1b78f5643f97683c54d0368fe | 0x103de892c43ceb3e5112aad93d9e888e65729e79 | operator | eoa_transferFrom | 0xdac17f958d2ee523a2206206994597c13d831ec7 | 0x103de892c43ceb3e5112aad93d9e888e65729e79 | T3 | eoa_spender_pull, wa_scam |  |
| 25667916 | 2026-08-02T14:52:47Z | 0x2a7012fac96c58efac3375c3e35a72f6ca9b052e6bc203a7bb061dedad654b9d | 0x1099ac30cdc4159b7a8c4acca27aa14628d5a93f | operator | eoa_transferFrom | 0xdac17f958d2ee523a2206206994597c13d831ec7 | 0x1099ac30cdc4159b7a8c4acca27aa14628d5a93f | T3 | eoa_spender_pull |  |
| 23874207 | 2025-11-25T07:02:11Z | 0x4dc09d01fb443dd711526926c3c8f6c816be2f3f38cc7678efb7ea6af35ce236 | 0x13d163241cc47d4e99bece791f75a3aa0f27fca8 | operator | eoa_transferFrom | 0xdac17f958d2ee523a2206206994597c13d831ec7 | 0x13d163241cc47d4e99bece791f75a3aa0f27fca8 | T3 | eoa_spender_pull, wa_scam |  |
| 23874208 | 2025-11-25T07:02:35Z | 0x9be2006b4154624588652bf6dde9efc52847067e9382b392afdeece938988f88 | 0x13d163241cc47d4e99bece791f75a3aa0f27fca8 | operator | eoa_transferFrom | 0xdac17f958d2ee523a2206206994597c13d831ec7 | 0x13d163241cc47d4e99bece791f75a3aa0f27fca8 | T3 | eoa_spender_pull, wa_scam |  |
| 22324192 | 2025-04-22T11:17:35Z | 0xe104146295a7e72f2a74bd2cf08fbd780d2405e43ad25b28b7940d079240d269 | 0x164e84226882c385940134f5b292cb89bc4feed6 | operator | eoa_transferFrom | 0xdac17f958d2ee523a2206206994597c13d831ec7 | 0x164e84226882c385940134f5b292cb89bc4feed6 | T3 | eoa_spender_pull |  |
| 25367261 | 2026-06-21T16:48:35Z | 0x91ccca5d16b531ccc06254071787c4a01cf398089d8aa9538202bc0085950b6b | 0x164e84226882c385940134f5b292cb89bc4feed6 | drainer_contract | pull_via_contract | 0x164e84226882c385940134f5b292cb89bc4feed6 | 0x164e84226882c385940134f5b292cb89bc4feed6 | T3 | eoa_spender_pull |  |
| 22085139 | 2025-03-20T02:38:11Z | 0xd20dea9b429538f70630dd16182ef7ef6add15a497a0418d251f2c398edb5094 | 0x1807823deb1ca3ff5f94640af39c61745dde6dd0 | operator | eoa_transferFrom | 0x95ad61b0a150d79219dcf64e1e6cc01f0b64c4ce | 0x1807823deb1ca3ff5f94640af39c61745dde6dd0 | T3 | eoa_spender_pull |  |
| 22197638 | 2025-04-04T19:26:11Z | 0x5413807679360691a40966f67ba0368eae869bc095c9fbda6dab096e93ac416d | 0x1c43785f37bde0e557357d4a88c25872ea57b649 | operator | eoa_transferFrom | 0xdac17f958d2ee523a2206206994597c13d831ec7 | 0x1c43785f37bde0e557357d4a88c25872ea57b649 | T3 | eoa_spender_pull, wa_scam |  |
| 22197642 | 2025-04-04T19:26:59Z | 0xa2ce7aaff6e9f2ca923da8ad68ecb0bd5e80b0059b70faed87847eb94944bfd7 | 0x1c43785f37bde0e557357d4a88c25872ea57b649 | operator | eoa_transferFrom | 0xdac17f958d2ee523a2206206994597c13d831ec7 | 0x1c43785f37bde0e557357d4a88c25872ea57b649 | T3 | eoa_spender_pull, wa_scam |  |
| 22197660 | 2025-04-04T19:30:35Z | 0xfe7dfcef43b9742fc32f0576501eab21f41caafd3b5bd0b44de41ed658942c0e | 0x1c43785f37bde0e557357d4a88c25872ea57b649 | operator | eoa_transferFrom | 0xdac17f958d2ee523a2206206994597c13d831ec7 | 0x1c43785f37bde0e557357d4a88c25872ea57b649 | T3 | eoa_spender_pull, wa_scam |  |
| 23873909 | 2025-11-25T06:02:11Z | 0xbf7c848d792fd88fa1a8e37672a53660cdee726a975888e216e9dac9acc83e3a | 0x1c43785f37bde0e557357d4a88c25872ea57b649 | operator | eoa_transferFrom | 0xdac17f958d2ee523a2206206994597c13d831ec7 | 0x1c43785f37bde0e557357d4a88c25872ea57b649 | T3 | eoa_spender_pull, wa_scam |  |
| 23874020 | 2025-11-25T06:24:47Z | 0x6f33f8a4b2ccbc933823d79002d4180e2f8fe0a758798d0ef43e503a5d834b30 | 0x2f2b4eeb3737103174de546b594749052eaa1401 | operator | eoa_transferFrom | 0xdac17f958d2ee523a2206206994597c13d831ec7 | 0x2f2b4eeb3737103174de546b594749052eaa1401 | T3 | eoa_spender_pull, wa_scam |  |
| 23874022 | 2025-11-25T06:25:11Z | 0xbe4804b5999d8f74abcce65937a9aae470dbcaeea67ac3ae082986c787618158 | 0x2f2b4eeb3737103174de546b594749052eaa1401 | operator | eoa_transferFrom | 0xdac17f958d2ee523a2206206994597c13d831ec7 | 0x2f2b4eeb3737103174de546b594749052eaa1401 | T3 | eoa_spender_pull, wa_scam |  |
| 23873926 | 2025-11-25T06:05:47Z | 0x7f782478b05afcc7923067e9b1f55e718dbe762f88969e331f85e6f04091f78d | 0x2ff93158c9ed52344864374ed11eb2495f7376e5 | operator | eoa_transferFrom | 0xdac17f958d2ee523a2206206994597c13d831ec7 | 0x2ff93158c9ed52344864374ed11eb2495f7376e5 | T3 | eoa_spender_pull, wa_scam |  |
| 22303566 | 2025-04-19T14:11:59Z | 0x0eefe18258736e9c6497c01556837569a9e8b897aba6e6d2923a7c4e57074738 | 0x39bc02af76ca261b9bc1ff9bf54696d79ffff059 | operator | eoa_transferFrom | 0x4da27a545c0c5b758a6ba100e3a049001de870f5 |  | - |  |  |
| 22303570 | 2025-04-19T14:12:47Z | 0x4fd66798b2ddd82bbc8353c83ffc545c41b32d14b786d83130deac211accbe86 | 0x39bc02af76ca261b9bc1ff9bf54696d79ffff059 | operator | eoa_transferFrom | 0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48 |  | - |  |  |
| 23615981 | 2025-10-20T02:55:11Z | 0xf681fbcfc362621fe3b4ab564138f8836c1432dea4c9b0310d557d3a9500bab0 | 0x433d46d0c76841ef7fe48aee4399801ada3cadda | drainer_contract | pull_via_contract | 0x433d46d0c76841ef7fe48aee4399801ada3cadda |  | - |  |  |
| 22146496 | 2025-03-28T16:06:35Z | 0x2a61da673dae71e10ba8dcdd98a6f469758635e38ea39f02b8de68c44d9a8199 | 0x43addb2a61e752aa50b9cc54ecd9c255b903276e | operator | eoa_transferFrom | 0xdac17f958d2ee523a2206206994597c13d831ec7 | 0x43addb2a61e752aa50b9cc54ecd9c255b903276e | T3 | eoa_spender_pull, wa_scam |  |
| 22458419 | 2025-05-11T06:49:11Z | 0x6eed6c54d1c1a4347da2c80c3610b8c6e2bf7a199278c92fd93ed3f1e9c8a206 | 0x43addb2a61e752aa50b9cc54ecd9c255b903276e | operator | eoa_transferFrom | 0xdac17f958d2ee523a2206206994597c13d831ec7 | 0x43addb2a61e752aa50b9cc54ecd9c255b903276e | T3 | eoa_spender_pull, wa_scam |  |
| 25565751 | 2026-07-19T09:06:47Z | 0xbf0bd28bb1d86fd07d029fbb313acf1e504dd297118da6ea897ef87264d567ce | 0x43addb2a61e752aa50b9cc54ecd9c255b903276e | operator | eoa_transferFrom | 0x389999216860ab8e0175387a0c90e5c52522c945 | 0x43addb2a61e752aa50b9cc54ecd9c255b903276e | T3 | eoa_spender_pull, wa_scam |  |
| 25795408 | 2026-08-20T09:22:59Z | 0xda5932a780af110af6647f25d2098b0d3bf6980f08854a8c35e001f40780facc | 0x43addb2a61e752aa50b9cc54ecd9c255b903276e | operator | eoa_transferFrom | 0xdac17f958d2ee523a2206206994597c13d831ec7 | 0x43addb2a61e752aa50b9cc54ecd9c255b903276e | T3 | eoa_spender_pull, wa_scam |  |
| 23202453 | 2025-08-23T08:00:23Z | 0x4bbe4f9c5ae2886b4e2f69d5f439abf6a29bcb973f29f646205df69059a40ae1 | 0x4d44d92143ac426fa84c864f9d282ca14b60a45b | operator | eoa_transferFrom | 0xdac17f958d2ee523a2206206994597c13d831ec7 | 0x4d44d92143ac426fa84c864f9d282ca14b60a45b | T2 | eoa_spender_multi, eoa_spender_pull, wa_scam |  |
| 23202465 | 2025-08-23T08:02:47Z | 0xe81c323735d1a6e014c3fe5178a010a1e80745ce484627788df2dafa4ec78602 | 0x4d44d92143ac426fa84c864f9d282ca14b60a45b | operator | eoa_transferFrom | 0xdac17f958d2ee523a2206206994597c13d831ec7 | 0x4d44d92143ac426fa84c864f9d282ca14b60a45b | T2 | eoa_spender_multi, eoa_spender_pull, wa_scam |  |
| 23202468 | 2025-08-23T08:03:23Z | 0x72f122e063e33990cd2591f3e6508a21a8e14600cf1ebe1d8453aadc78fca615 | 0x4d44d92143ac426fa84c864f9d282ca14b60a45b | operator | eoa_transferFrom | 0xdac17f958d2ee523a2206206994597c13d831ec7 | 0x4d44d92143ac426fa84c864f9d282ca14b60a45b | T2 | eoa_spender_multi, eoa_spender_pull, wa_scam |  |
| 23202470 | 2025-08-23T08:03:47Z | 0x09966aeb5461567b7b41c8a9a6c8d04b079acc64347c110bd13aec5c436d4147 | 0x4d44d92143ac426fa84c864f9d282ca14b60a45b | operator | eoa_transferFrom | 0xdac17f958d2ee523a2206206994597c13d831ec7 | 0x4d44d92143ac426fa84c864f9d282ca14b60a45b | T2 | eoa_spender_multi, eoa_spender_pull, wa_scam |  |
| 23325910 | 2025-09-09T13:42:47Z | 0xa13bb846d786a7d0f14bd2ea85cfb15afcc1d96d4b89a6ae42f94eefec00bac9 | 0x4e1afe1a284e5b39a596e64020a48c2049362c3b | operator | pull_via_contract | 0x79ce8f93063f8be4573a58f250b003859ebb7a24 |  | - |  |  |
| 25667920 | 2026-08-02T14:53:35Z | 0x3d5f2a855c57975eb8d28a1fc8cd5e041e42ef8af90f1558d9f5d65523d5886f | 0x55c3f34c992cbac8d966609773fbc441dddd9c45 | operator | eoa_transferFrom | 0xdac17f958d2ee523a2206206994597c13d831ec7 | 0x55c3f34c992cbac8d966609773fbc441dddd9c45 | T3 | eoa_spender_pull |  |
| 25667921 | 2026-08-02T14:53:47Z | 0x373d1a921fe7a9d84628472045e2ade3936ecfa5106f61c2cccd8132245fe2c7 | 0x55c3f34c992cbac8d966609773fbc441dddd9c45 | operator | eoa_transferFrom | 0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48 | 0x55c3f34c992cbac8d966609773fbc441dddd9c45 | T3 | eoa_spender_pull |  |
| 23673763 | 2025-10-28T05:12:35Z | 0x05558e95b1e0524a3cf93959692ea9d22a47cd87ec8c794fdb85047ad5af8dea | 0x5a077462e7fb9606f369d665a7648f9da1634d55 | operator | eoa_transferFrom | 0xdac17f958d2ee523a2206206994597c13d831ec7 | 0x5a077462e7fb9606f369d665a7648f9da1634d55 | T3 | eoa_spender_pull, wa_scam |  |
| 23866647 | 2025-11-24T05:29:35Z | 0x6e5f9539dad0a0765e0d9bfe2ddfeab5e8b75f434d925ee3372e22c1cf5be9f7 | 0x5a077462e7fb9606f369d665a7648f9da1634d55 | operator | eoa_transferFrom | 0xdac17f958d2ee523a2206206994597c13d831ec7 | 0x5a077462e7fb9606f369d665a7648f9da1634d55 | T3 | eoa_spender_pull, wa_scam |  |
| 23866901 | 2025-11-24T06:20:47Z | 0x4f5154cfa893366202304742b2a6e8bf3c5fc2943cceb0529881e08107df3372 | 0x5b55f322c9b72f00e7b451e8dde6555dbfdbdb9e | operator | eoa_transferFrom | 0xdac17f958d2ee523a2206206994597c13d831ec7 | 0x5b55f322c9b72f00e7b451e8dde6555dbfdbdb9e | T2 | eoa_spender_multi, eoa_spender_pull |  |
| 23866905 | 2025-11-24T06:21:35Z | 0x8616431529b1c0ad52e3461a9bdff4843018f06947e18dd98fd06ce7430d0488 | 0x5b55f322c9b72f00e7b451e8dde6555dbfdbdb9e | operator | eoa_transferFrom | 0xdac17f958d2ee523a2206206994597c13d831ec7 | 0x5b55f322c9b72f00e7b451e8dde6555dbfdbdb9e | T2 | eoa_spender_multi, eoa_spender_pull |  |
| 23866907 | 2025-11-24T06:21:59Z | 0x379a3edb8dc3271865395f8bfa764dd46e92970a4f159a7c0d7befa0156c137d | 0x5b55f322c9b72f00e7b451e8dde6555dbfdbdb9e | operator | eoa_transferFrom | 0xdac17f958d2ee523a2206206994597c13d831ec7 | 0x5b55f322c9b72f00e7b451e8dde6555dbfdbdb9e | T2 | eoa_spender_multi, eoa_spender_pull |  |
| 23866912 | 2025-11-24T06:22:59Z | 0xbfa2a74038e4b71e2373d79d82f38098ced8956d35b38834a075072750c5c7fe | 0x5b55f322c9b72f00e7b451e8dde6555dbfdbdb9e | operator | eoa_transferFrom | 0xdac17f958d2ee523a2206206994597c13d831ec7 | 0x5b55f322c9b72f00e7b451e8dde6555dbfdbdb9e | T2 | eoa_spender_multi, eoa_spender_pull |  |
| 22457544 | 2025-05-11T03:52:11Z | 0x512607dacf60205319b1daebba0e11888d5bd7d2177328a5050e76e0028c0c68 | 0x62474d6c379788be4f9cddc0e67c3013a78522d9 | operator | eoa_transferFrom | 0x4a220e6096b25eadb88358cb44068a3248254675 | 0x62474d6c379788be4f9cddc0e67c3013a78522d9 | T3 | eoa_spender_pull |  |
| 25365051 | 2026-06-21T09:24:23Z | 0x653b1fc006a90f978cc804fb536279564db7174412353f5d011ca4917a148d5b | 0x67a8142d93ec172175bccce4969873058b56290a | drainer_contract | pull_via_contract | 0x67a8142d93ec172175bccce4969873058b56290a | 0x67a8142d93ec172175bccce4969873058b56290a | T3 | eoa_spender_pull |  |
| 25367261 | 2026-06-21T16:48:35Z | 0xf8d06b764112c6e3c1529edbe7cda1667d7b241c459163e80da5fb70932ba88c | 0x67a8142d93ec172175bccce4969873058b56290a | drainer_contract | pull_via_contract | 0x67a8142d93ec172175bccce4969873058b56290a | 0x67a8142d93ec172175bccce4969873058b56290a | T3 | eoa_spender_pull |  |
| 26431726 | 2026-11-17T02:17:47Z | 0xa256a94d2c8a482b21341dbda4d0618f284cd9a704fd524721b6a881a88524ca | 0x689b378f9c1ab4c37d25112ca6b8da787eca72ba | operator | eoa_transferFrom | 0xdac17f958d2ee523a2206206994597c13d831ec7 | 0x689b378f9c1ab4c37d25112ca6b8da787eca72ba | T3 | eoa_spender_pull |  |
| 22197623 | 2025-04-04T19:23:11Z | 0x29143d6367e901fff2b513338ea7c2e58dcf131be37087161ac25b49396bf7f4 | 0x7502359202de8f2ebaa7229850b4387e1da43b63 | operator | eoa_transferFrom | 0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48 | 0x7502359202de8f2ebaa7229850b4387e1da43b63 | T3 | eoa_spender_pull |  |
| 26393902 | 2026-11-11T19:53:47Z | 0x24e3c6c676f61c22d12962f628af4d14de82d441c89852737b0035b3022b5b1b | 0x7586983ed3b58e71a5415edd559c1fb210e18db6 | drainer_contract | pull_via_contract | 0x7586983ed3b58e71a5415edd559c1fb210e18db6 | 0x7586983ed3b58e71a5415edd559c1fb210e18db6 | T3 | eoa_spender_pull |  |
| 23238904 | 2025-08-28T10:04:59Z | 0x2ae8c5ca683410ef48256244aa3b35f38662da491b0330cdfa703acea1001adb | 0x7598d3e6e95f0ab85ac74f041dc92a1187b8184e | operator | eoa_transferFrom | 0xdac17f958d2ee523a2206206994597c13d831ec7 | 0x7598d3e6e95f0ab85ac74f041dc92a1187b8184e | T2 | eoa_spender_multi, eoa_spender_pull, wa_scam |  |
| 23238908 | 2025-08-28T10:05:47Z | 0xc2f337cd4694b900dd73bed9ed607fdb52f9f316426cfebb97209395e621f0a4 | 0x7598d3e6e95f0ab85ac74f041dc92a1187b8184e | operator | eoa_transferFrom | 0xdac17f958d2ee523a2206206994597c13d831ec7 | 0x7598d3e6e95f0ab85ac74f041dc92a1187b8184e | T2 | eoa_spender_multi, eoa_spender_pull, wa_scam |  |
| 23238910 | 2025-08-28T10:06:11Z | 0x33f407217d4f833571349227d8a892edf110f454d79920f8a4c6f04e8e1c67ba | 0x7598d3e6e95f0ab85ac74f041dc92a1187b8184e | operator | eoa_transferFrom | 0xdac17f958d2ee523a2206206994597c13d831ec7 | 0x7598d3e6e95f0ab85ac74f041dc92a1187b8184e | T2 | eoa_spender_multi, eoa_spender_pull, wa_scam |  |
| 23238915 | 2025-08-28T10:07:11Z | 0x4eb1854978b193e3bb2c7f8300938f0f6409dfd58962d80d496af92e8df76512 | 0x7598d3e6e95f0ab85ac74f041dc92a1187b8184e | operator | eoa_transferFrom | 0xdac17f958d2ee523a2206206994597c13d831ec7 | 0x7598d3e6e95f0ab85ac74f041dc92a1187b8184e | T2 | eoa_spender_multi, eoa_spender_pull, wa_scam |  |
| 23155056 | 2025-08-16T17:20:23Z | 0xc75d1ff71213a6bf5d3e6160687e63b0c79b13f8d08ec98de53e7bd28424f2ea | 0x7b5f326d9e8b36237d17a1918f2fd99992619eae | drainer_contract | pull_via_contract | 0x7b5f326d9e8b36237d17a1918f2fd99992619eae | 0x7b5f326d9e8b36237d17a1918f2fd99992619eae | T3 | eoa_spender_pull |  |
| 22696084 | 2025-06-13T13:57:59Z | 0x7a92dca4270a3f659b6df6499d4070a256afacecea1c66419bbc2a7a7fa7c4a5 | 0x8413c544095f7e69d4ad3bfcf4b77deedda0cc39 | operator | eoa_transferFrom | 0xf411903cbc70a74d22900a5de66a2dda66507255 |  | - |  |  |
| 22696084 | 2025-06-13T13:57:59Z | 0xd8cc2ba0dbdd9add675f8956837ed9164ef18edfce694b2454c99df2100e8919 | 0x8413c544095f7e69d4ad3bfcf4b77deedda0cc39 | operator | eoa_transferFrom | 0xf411903cbc70a74d22900a5de66a2dda66507255 |  | - |  |  |
| 23095005 | 2025-08-08T07:58:59Z | 0xca37c787a6d8c21e09348ba429c3599cd59585a47f54f50b35fcde33e76362fd | 0x8413c544095f7e69d4ad3bfcf4b77deedda0cc39 | operator | eoa_transferFrom | 0x656c00e1bcd96f256f224ad9112ff426ef053733 |  | - |  |  |
| 23095005 | 2025-08-08T07:58:59Z | 0xc5fade4c60ffcbc5024c8f7c9315fb76e483d298bf4ae79a0f58c8aac41a46f7 | 0x8413c544095f7e69d4ad3bfcf4b77deedda0cc39 | operator | eoa_transferFrom | 0x656c00e1bcd96f256f224ad9112ff426ef053733 |  | - |  |  |
| 22888968 | 2025-07-10T13:05:59Z | 0x6b8f09de82f4a18aadc5cbc2149dc0f00bb219ba78801f12f57fd999b95b8380 | 0x857d06e3a3c9b789b32d72f149075e4c15205f10 | operator | eoa_transferFrom | 0xdac17f958d2ee523a2206206994597c13d831ec7 |  | - |  |  |
| 24277447 | 2026-01-20T17:20:47Z | 0x8711383de8e488b1aa4b54230c6573ea6cd335dbe5fee9938b79b906fde9a91b | 0x857d06e3a3c9b789b32d72f149075e4c15205f10 | operator | eoa_transferFrom | 0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48 |  | - |  |  |
| 25057325 | 2026-05-09T11:48:35Z | 0x203735165ba12dcd09683a36e15ab6f94744b40395bea03003d62f8955174712 | 0x857d06e3a3c9b789b32d72f149075e4c15205f10 | operator | eoa_transferFrom | 0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48 |  | - |  |  |
| 25057326 | 2026-05-09T11:48:47Z | 0xda21544f9788ac72966c6d1bf9521311458ec67590ba8858b716e5bb1ea79d2a | 0x857d06e3a3c9b789b32d72f149075e4c15205f10 | operator | eoa_transferFrom | 0xdac17f958d2ee523a2206206994597c13d831ec7 |  | - |  |  |
| 23531185 | 2025-10-08T06:15:35Z | 0xac9d8ee37e03d52f3d94eb4b1c5115986993d43513f62b23d421a55f4c1113ab | 0x85ab0f9ad5f4a09fc81f3a18140be9db92d64266 | operator | eoa_transferFrom | 0xdac17f958d2ee523a2206206994597c13d831ec7 | 0x85ab0f9ad5f4a09fc81f3a18140be9db92d64266 | T2 | eoa_spender_multi, eoa_spender_pull, wa_scam |  |
| 23531196 | 2025-10-08T06:17:47Z | 0x871b0c060a0c3cf4f9fb05e8c24d8852e77896dc881dbcea8d7253f3870c0ef5 | 0x85ab0f9ad5f4a09fc81f3a18140be9db92d64266 | operator | eoa_transferFrom | 0xdac17f958d2ee523a2206206994597c13d831ec7 | 0x85ab0f9ad5f4a09fc81f3a18140be9db92d64266 | T2 | eoa_spender_multi, eoa_spender_pull, wa_scam |  |
| 23531210 | 2025-10-08T06:20:35Z | 0x1efd216341f11fd2ab0082c98a02c26fe88d1c6dd950aa6a7e9ca86b7e425da6 | 0x85ab0f9ad5f4a09fc81f3a18140be9db92d64266 | operator | eoa_transferFrom | 0xdac17f958d2ee523a2206206994597c13d831ec7 | 0x85ab0f9ad5f4a09fc81f3a18140be9db92d64266 | T2 | eoa_spender_multi, eoa_spender_pull, wa_scam |  |
| 23890873 | 2025-11-27T15:14:59Z | 0x38b9f2b132f5df7a1c639d90a6b2943147daab5399dbb6da0add0fed1ba16763 | 0x85ab0f9ad5f4a09fc81f3a18140be9db92d64266 | operator | eoa_transferFrom | 0xdac17f958d2ee523a2206206994597c13d831ec7 | 0x85ab0f9ad5f4a09fc81f3a18140be9db92d64266 | T2 | eoa_spender_multi, eoa_spender_pull, wa_scam |  |
| 22752478 | 2025-06-21T11:15:23Z | 0x0c4425013fec755e939591b3aeccec0e110d28d2406ccafe4afd989c26a8043c | 0x8760513f944be842ffb4888fde71cad1e2a394c3 | operator | eoa_transferFrom | 0xc5fb36dd2fb59d3b98deff88425a3f425ee469ed |  | - |  |  |
| 22084666 | 2025-03-20T01:02:23Z | 0xdd967c1a36b54379c959992132dabb9fb995e94579879038dfe463cbe20fb058 | 0x8a1b0379e31bc4642f3d63e0c56f39753d4caafb | operator | eoa_transferFrom | 0x823556202e86763853b40e9cde725f412e294689 | 0x8a1b0379e31bc4642f3d63e0c56f39753d4caafb | T3 | eoa_spender_pull |  |
| 22197359 | 2025-04-04T18:30:23Z | 0x972cd9f7dfbfa4b9c5258349daaee037847b100c6bd3a492b5c23de462489280 | 0x90a3c256cbc46175150356e92df0a2bd25725dc1 | operator | eoa_transferFrom | 0xdac17f958d2ee523a2206206994597c13d831ec7 | 0x90a3c256cbc46175150356e92df0a2bd25725dc1 | T3 | eoa_spender_pull, wa_scam |  |
| 22197367 | 2025-04-04T18:31:59Z | 0x4193622dfe6df3db37d414ede5781481ba16bdc59c2ae4cbf77eac42bbd91845 | 0x90a3c256cbc46175150356e92df0a2bd25725dc1 | operator | eoa_transferFrom | 0xdac17f958d2ee523a2206206994597c13d831ec7 | 0x90a3c256cbc46175150356e92df0a2bd25725dc1 | T3 | eoa_spender_pull, wa_scam |  |
| 23674512 | 2025-10-28T07:43:47Z | 0x857c40426cfefc3473ba2e0a7939efb8581a7bb7af1c433a0653e22cc067adde | 0x90a3c256cbc46175150356e92df0a2bd25725dc1 | operator | eoa_transferFrom | 0xdac17f958d2ee523a2206206994597c13d831ec7 | 0x90a3c256cbc46175150356e92df0a2bd25725dc1 | T3 | eoa_spender_pull, wa_scam |  |
| 23674525 | 2025-10-28T07:46:23Z | 0xd0fd81a0de90871c9694c1f59d10701bb673a60b9917f499653a55ea3bc9a80f | 0x90a3c256cbc46175150356e92df0a2bd25725dc1 | operator | eoa_transferFrom | 0xdac17f958d2ee523a2206206994597c13d831ec7 | 0x90a3c256cbc46175150356e92df0a2bd25725dc1 | T3 | eoa_spender_pull, wa_scam |  |
| 25367267 | 2026-06-21T16:49:47Z | 0x5ee2ed4dee1e189f9d313fedf76f2bbffa22c07c7b0074d66226538af06ac0d9 | 0xa2d316e5a1c1fa2e1c8c420e29580da773335678 | drainer_contract | pull_via_contract | 0xa2d316e5a1c1fa2e1c8c420e29580da773335678 | 0xa2d316e5a1c1fa2e1c8c420e29580da773335678 | T3 | eoa_spender_pull |  |
| 25367824 | 2026-06-21T18:41:11Z | 0x5422de3297c33567c3abac165a3d50fe29d88d20ff9d734fa6051cf7c506ea43 | 0xa2d316e5a1c1fa2e1c8c420e29580da773335678 | drainer_contract | pull_via_contract | 0xa2d316e5a1c1fa2e1c8c420e29580da773335678 | 0xa2d316e5a1c1fa2e1c8c420e29580da773335678 | T3 | eoa_spender_pull |  |
| 25367826 | 2026-06-21T18:41:35Z | 0x51457ade3e3126f130ba2b8b86c6ecebfefb3eee039096ba405cec53768e8449 | 0xa2d316e5a1c1fa2e1c8c420e29580da773335678 | drainer_contract | pull_via_contract | 0xa2d316e5a1c1fa2e1c8c420e29580da773335678 | 0xa2d316e5a1c1fa2e1c8c420e29580da773335678 | T3 | eoa_spender_pull |  |
| 23674051 | 2025-10-28T06:10:47Z | 0x43f8d0ad96c7a9661cf3befe1b1f69f09b0b6857eb932057c873f098a42dbef8 | 0xadd0e097b961572b2a1f5de572c622eef97e3d82 | operator | eoa_transferFrom | 0xdac17f958d2ee523a2206206994597c13d831ec7 | 0xadd0e097b961572b2a1f5de572c622eef97e3d82 | T2 | eoa_spender_multi, eoa_spender_pull, wa_scam |  |
| 23674058 | 2025-10-28T06:12:11Z | 0xf93615c9df80afe9c4a68a011d0fb4b42b2217e09a0f2390d01097ae1045f0bc | 0xadd0e097b961572b2a1f5de572c622eef97e3d82 | operator | eoa_transferFrom | 0xdac17f958d2ee523a2206206994597c13d831ec7 | 0xadd0e097b961572b2a1f5de572c622eef97e3d82 | T2 | eoa_spender_multi, eoa_spender_pull, wa_scam |  |
| 23674065 | 2025-10-28T06:13:35Z | 0x913df4b5a0eeb6b22d11867e95985d9cb4e49b0b52cb3257287eb02b66070f31 | 0xadd0e097b961572b2a1f5de572c622eef97e3d82 | operator | eoa_transferFrom | 0xdac17f958d2ee523a2206206994597c13d831ec7 | 0xadd0e097b961572b2a1f5de572c622eef97e3d82 | T2 | eoa_spender_multi, eoa_spender_pull, wa_scam |  |
| 23674072 | 2025-10-28T06:14:59Z | 0xae187fdfcd3bf87ca2fc7a47af73fcf0bc21f6fbb200caa83b349586faeb7870 | 0xadd0e097b961572b2a1f5de572c622eef97e3d82 | operator | eoa_transferFrom | 0xdac17f958d2ee523a2206206994597c13d831ec7 | 0xadd0e097b961572b2a1f5de572c622eef97e3d82 | T2 | eoa_spender_multi, eoa_spender_pull, wa_scam |  |
| 23674223 | 2025-10-28T06:45:23Z | 0x660d4f9d087c3f6938584c06e6813692d648fe1e8b72a33b67b118da194b3c7f | 0xae194392cb4bb3ce69d53f88275a52dd2ed3c61a | operator | eoa_transferFrom | 0xdac17f958d2ee523a2206206994597c13d831ec7 | 0xae194392cb4bb3ce69d53f88275a52dd2ed3c61a | T2 | eoa_spender_multi, eoa_spender_pull, wa_scam |  |
| 23674232 | 2025-10-28T06:47:23Z | 0x856613747b8060e71a9e9a9f93fb84b2d5cc5bc4a1c35695d6401467e3e4be31 | 0xae194392cb4bb3ce69d53f88275a52dd2ed3c61a | operator | eoa_transferFrom | 0xdac17f958d2ee523a2206206994597c13d831ec7 | 0xae194392cb4bb3ce69d53f88275a52dd2ed3c61a | T2 | eoa_spender_multi, eoa_spender_pull, wa_scam |  |
| 23674242 | 2025-10-28T06:49:23Z | 0xf7678a0b01d09c26683c9bab48c86cfa7c7f101aa2cdae4a30ff3aa5745b076c | 0xae194392cb4bb3ce69d53f88275a52dd2ed3c61a | operator | eoa_transferFrom | 0xdac17f958d2ee523a2206206994597c13d831ec7 | 0xae194392cb4bb3ce69d53f88275a52dd2ed3c61a | T2 | eoa_spender_multi, eoa_spender_pull, wa_scam |  |
| 23674256 | 2025-10-28T06:52:23Z | 0x84422689b9752b847d925ff8c67e154219e2592331ebdcb77709645c92d7581a | 0xae194392cb4bb3ce69d53f88275a52dd2ed3c61a | operator | eoa_transferFrom | 0xdac17f958d2ee523a2206206994597c13d831ec7 | 0xae194392cb4bb3ce69d53f88275a52dd2ed3c61a | T2 | eoa_spender_multi, eoa_spender_pull, wa_scam |  |
| 21672354 | 2025-01-21T10:45:47Z | 0xd328f027e029688096a4039bb96a659a308dd47f74e3c166c0d28fc585220741 | 0xb8659dc05a5668e502009513e0bfa5cb9bf1579c | operator | eoa_transferFrom | 0xdac17f958d2ee523a2206206994597c13d831ec7 | 0xb8659dc05a5668e502009513e0bfa5cb9bf1579c | T3 | eoa_spender_pull |  |
| 21841012 | 2025-02-14T00:04:23Z | 0x38ded7ba61c2f43356199269c06ab94ad8046913a1249797aae6ce56f207f555 | 0xb8659dc05a5668e502009513e0bfa5cb9bf1579c | operator | eoa_transferFrom | 0xdac17f958d2ee523a2206206994597c13d831ec7 | 0xb8659dc05a5668e502009513e0bfa5cb9bf1579c | T3 | eoa_spender_pull |  |
| 22982931 | 2025-07-23T16:02:59Z | 0xb43307968f033bf9cd31f63410d889a02cca5c95461c5a47bd0bac7f644ec5a4 | 0xb8659dc05a5668e502009513e0bfa5cb9bf1579c | operator | eoa_transferFrom | 0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48 | 0xb8659dc05a5668e502009513e0bfa5cb9bf1579c | T3 | eoa_spender_pull |  |
| 22988983 | 2025-07-24T12:21:59Z | 0xe9f8c8618cde2ab61b36f45a16a31aea986aa084bbd66fa3f547f6c3df05cc0c | 0xb8659dc05a5668e502009513e0bfa5cb9bf1579c | operator | eoa_transferFrom | 0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2 | 0xb8659dc05a5668e502009513e0bfa5cb9bf1579c | T3 | eoa_spender_pull |  |
| 22080208 | 2025-03-19T10:05:35Z | 0xde92da656535c72d5922733dc34750a23ff67994fe9f92c34e4dc304f3070a86 | 0xc1e3224ecec7e216ca2acfba621e523743168c72 | operator | eoa_transferFrom | 0xbbc2ae13b23d715c30720f079fcd9b4a74093505 | 0xc1e3224ecec7e216ca2acfba621e523743168c72 | T3 | eoa_spender_pull |  |
| 25565723 | 2026-07-19T09:01:11Z | 0x362b141f5a550e0e740acb878d675c347ceadaaa6469b9c386b25706b4dcde7f | 0xc1f908863feca9f0b352d31606173d13fa113134 | operator | eoa_transferFrom | 0x1e2f15302b90edde696593607b6bd444b64e8f02 | 0xc1f908863feca9f0b352d31606173d13fa113134 | T3 | eoa_spender_pull |  |
| 25565735 | 2026-07-19T09:03:35Z | 0x148fae046d506d3857d7ac600a1e601a26bffc16f323220e6b4719851d8cc05f | 0xc1f908863feca9f0b352d31606173d13fa113134 | operator | eoa_transferFrom | 0xee06a81a695750e71a662b51066f2c74cf4478a0 | 0xc1f908863feca9f0b352d31606173d13fa113134 | T3 | eoa_spender_pull |  |
| 25798993 | 2026-08-20T21:22:23Z | 0x35d94a727536e86992a28aca7a3b110848bf4e5cf93b78959044b5e2082dcc56 | 0xc1f908863feca9f0b352d31606173d13fa113134 | operator | eoa_transferFrom | 0xdac17f958d2ee523a2206206994597c13d831ec7 | 0xc1f908863feca9f0b352d31606173d13fa113134 | T3 | eoa_spender_pull |  |
| 26462372 | 2026-11-21T08:46:23Z | 0xf732dabadf19704d1037dd5f41e4f95249db9724e51b9b9e307e99bd79817f47 | 0xc1f908863feca9f0b352d31606173d13fa113134 | operator | eoa_transferFrom | 0x505b5eda5e25a67e1c24a2bf1a527ed9eb88bf04 | 0xc1f908863feca9f0b352d31606173d13fa113134 | T3 | eoa_spender_pull |  |
| 24118743 | 2025-12-29T13:56:23Z | 0x9fe6fbe920b1bb13261c4aed87c6e532f57f6d0ea48d7cc03d57ddd0b1c58522 | 0xc94c714c607d4e74aa78a1e6e6cb536ca4bd56a9 | operator | eoa_transferFrom | 0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48 | 0xc94c714c607d4e74aa78a1e6e6cb536ca4bd56a9 | T3 | eoa_spender_pull |  |
| 24444563 | 2026-02-13T01:25:11Z | 0x75e849a5fc43dec415b4ee2c8075678379ea6d9d8a8b35e556d96799b2b3b72c | 0xc94c714c607d4e74aa78a1e6e6cb536ca4bd56a9 | operator | eoa_transferFrom | 0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48 | 0xc94c714c607d4e74aa78a1e6e6cb536ca4bd56a9 | T3 | eoa_spender_pull |  |
| 25768838 | 2026-08-16T16:31:59Z | 0x39c2b37b71b0eec33cd13900a42865f47ae7d37fd0ae8141aa78f79c01f50cdd | 0xc94c714c607d4e74aa78a1e6e6cb536ca4bd56a9 | drainer_contract | pull_via_contract | 0xc94c714c607d4e74aa78a1e6e6cb536ca4bd56a9 | 0xc94c714c607d4e74aa78a1e6e6cb536ca4bd56a9 | T3 | eoa_spender_pull |  |
| 21564345 | 2025-01-06T08:51:23Z | 0x1daf0d9900529d1d4d9f7de4954e55a9bcf74866a68652631c6e3e22eefa5b28 | 0xd154ae1e290ae30772baaef8a3ce6603a910534f | operator | eoa_transferFrom | 0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48 | 0xd154ae1e290ae30772baaef8a3ce6603a910534f | T3 | eoa_spender_pull |  |
| 21842264 | 2025-02-14T04:17:11Z | 0xc5cf2d03eb20fce89197c47dac81b538642c8ca1c86e32169b03c54abe6a22df | 0xd154ae1e290ae30772baaef8a3ce6603a910534f | operator | eoa_transferFrom | 0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48 | 0xd154ae1e290ae30772baaef8a3ce6603a910534f | T3 | eoa_spender_pull |  |
| 25477771 | 2026-07-07T02:45:59Z | 0x1c70db22ff53f5beb7c5183d77b37e5ccc3e783d5005883a60faba20d48da1f1 | 0xd154ae1e290ae30772baaef8a3ce6603a910534f | operator | eoa_transferFrom | 0xdac17f958d2ee523a2206206994597c13d831ec7 | 0xd154ae1e290ae30772baaef8a3ce6603a910534f | T3 | eoa_spender_pull |  |
| 26400230 | 2026-11-12T17:02:23Z | 0xf9cd678c65be072435f40c6961350eee6413d42cd3bc2899486501b6e6ab9ccc | 0xd154ae1e290ae30772baaef8a3ce6603a910534f | operator | eoa_transferFrom | 0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48 | 0xd154ae1e290ae30772baaef8a3ce6603a910534f | T3 | eoa_spender_pull |  |
| 22995343 | 2025-07-25T09:42:59Z | 0x9d049e9788277af3a2154aaa3e9925fc97255d1d926228e56573c8a706a6f79a | 0xe4bb57cf97c6248efdaeb495a6123d8adf6f9bf2 | drainer_contract | pull_via_contract | 0xe4bb57cf97c6248efdaeb495a6123d8adf6f9bf2 |  | - |  |  |
| 22995346 | 2025-07-25T09:43:47Z | 0x169e161a6cdd611842a16b931becf544c781e418ddf8ff85df4837f6adac65d2 | 0xe4bb57cf97c6248efdaeb495a6123d8adf6f9bf2 | drainer_contract | pull_via_contract | 0xe4bb57cf97c6248efdaeb495a6123d8adf6f9bf2 |  | - |  |  |
| 23616062 | 2025-10-20T03:11:23Z | 0xa6031e6b56337f205dec81e3f09fcc690b74a3907f505f2b38a8754d731cbf60 | 0xe4bb57cf97c6248efdaeb495a6123d8adf6f9bf2 | drainer_contract | pull_via_contract | 0xe4bb57cf97c6248efdaeb495a6123d8adf6f9bf2 |  | - |  |  |
| 23616063 | 2025-10-20T03:11:35Z | 0x355651abb0625a4ebe95ba3fd0145e7c83f68085e2e4af1f7e630ffc1f17eacb | 0xe4bb57cf97c6248efdaeb495a6123d8adf6f9bf2 | drainer_contract | pull_via_contract | 0xe4bb57cf97c6248efdaeb495a6123d8adf6f9bf2 |  | - |  |  |
| 23926327 | 2025-12-02T14:18:35Z | 0xd4cab706397f1b612ce1319fc3d17397b0b37cd4d64b6c0b32c0718c02adad30 | 0xe64ad42e9ed6135b504f4c29ffe9d3a187bc14e2 | operator | via_allowlisted:KyberSwap MetaAggregationRouterV2 | 0x6131b5fae19ea4f9d964eac0408e4408b66337b5 |  | - |  |  |
| 23558997 | 2025-10-12T03:36:47Z | 0x60bbe40cfec10f1c72680106080fc95ea70eefbf28ec641d87d0bc8fb90a3842 | 0xed25a3fe82ef1364dcccf9476a2a0c48bfb1a94c | operator | via_allowlisted:MetaMask Swap Router | 0x881d40237659c251811cec9c364ef91dc08d300c |  | - |  |  |
| 22315842 | 2025-04-21T07:20:23Z | 0x03754d63ae55d1cf94b520494f3576ec18d22d8a488c92f29b1c60aa1d5697cc | 0xf16f322ccda034aad638c62588c0312d63868bd0 | operator | eoa_transferFrom | 0xdac17f958d2ee523a2206206994597c13d831ec7 | 0xf16f322ccda034aad638c62588c0312d63868bd0 | T3 | eoa_spender_pull |  |
| 22601703 | 2025-05-31T09:05:47Z | 0x1431852450dbb5664b61bc5f3858480b1a0fe4927ce84b9110ad575d4ffb4ec3 | 0xf16f322ccda034aad638c62588c0312d63868bd0 | operator | eoa_transferFrom | 0xdac17f958d2ee523a2206206994597c13d831ec7 | 0xf16f322ccda034aad638c62588c0312d63868bd0 | T3 | eoa_spender_pull |  |
| 23705795 | 2025-11-01T16:50:59Z | 0x77c0e3d1306dcdf8ffffeb2f3175ba2c980ffc21a11d38d46ad4d5af2ca84e01 | 0xf16f322ccda034aad638c62588c0312d63868bd0 | operator | eoa_transferFrom | 0xdac17f958d2ee523a2206206994597c13d831ec7 | 0xf16f322ccda034aad638c62588c0312d63868bd0 | T3 | eoa_spender_pull |  |
| 25709115 | 2026-08-08T08:41:23Z | 0x7bd13f0781bcc59e93618074068a70f49a3e657b200e36488090e59b6d133218 | 0xf16f322ccda034aad638c62588c0312d63868bd0 | operator | eoa_transferFrom | 0xdac17f958d2ee523a2206206994597c13d831ec7 | 0xf16f322ccda034aad638c62588c0312d63868bd0 | T3 | eoa_spender_pull |  |
| 22696073 | 2025-06-13T13:55:47Z | 0x6c31f0be142821d820a4f915dbe90ebfdda5fc25eb8ed97eb8bd551ea464719e | 0xfb4d3eb37bde8fa4b52c60aabe55b3cd9908ec73 | operator | eoa_transferFrom | 0x6982508145454ce325ddbe47a25d4ec3d2311933 |  | - |  |  |
| 22809015 | 2025-06-29T08:53:47Z | 0x1a68ecd15094fa5b416a4c7ad51ed94c2a87f8feaf37a96936c66a99eba8c249 | 0xfb4d3eb37bde8fa4b52c60aabe55b3cd9908ec73 | operator | eoa_transferFrom | 0x3a856d4effa670c54585a5d523e96513e148e95d |  | - |  |  |
| 22979412 | 2025-07-23T04:13:47Z | 0x2de0d0d5b14e45ff71a92e6c8f74fd1c96b3ac9ad0cfe0d68a03fe5dfa3d7d7d | 0xfb4d3eb37bde8fa4b52c60aabe55b3cd9908ec73 | operator | via_allowlisted:Permit2 | 0x000000000022d473030f116ddee9f6b43ac78ba3 |  | - |  |  |
| 23915632 | 2025-12-01T02:23:35Z | 0x94f9f14ebf66b615a22d089ab6bef23f9e4b0c021b9da05f797ec3c8d0dfa3fd | 0xfb4d3eb37bde8fa4b52c60aabe55b3cd9908ec73 | operator | eoa_transferFrom | 0xed35af169af46a02ee13b9d79eb57d6d68c1749e |  | - |  |  |

## False-positive candidates (T1/T2, not an incident target of the component)

| address | tier | labels | class | wa label | contract name | evidence |
|---|---|---|---|---|---|---|
| 0x00004322aaaaa248873c2601528769db860e0000 | T2 | split_pull | unverified / unknown |  |  | split_pull 0x5067f6113e235486ecaeaaf94a95f8f02b86f43df84e87e3a4e37cbf645854fe |
| 0x00004fd598eacfda276553cdf9f1be668eab0000 | T2 | split_pull | unverified / unknown |  |  | split_pull 0x0ea425c9ca560eec30587cff3cdb0580874bfbd8e851ff9218cd83ef5ad18c8c |
| 0x9b743560baf6d31ed20fdff17ba2e8e5b1bacf43 | T2 | split_pull | unverified / unknown |  |  | split_pull 0xfeaf7f386fc8a53f5e4e28f0cb059c85f7cd8fbc3da4bbc4be58124d71cfa6fb |
| 0xc212efe0a52ef24c45476e195e8eccf178bc4bbd | T2 | split_pull | unverified / unknown |  |  | split_pull 0x523b6a6bf453331f32ca9e3ddf91f5bd035b499965046b1273fc4f346c8e15bf |
| 0x6ec5fa655c65311325257cb12d2ac01aa73a50f9 | T2 | split_pull | verified contract |  | Poisonooor | split_pull 0xf927325bca36a72ed480fe8328aba1e6528dbf7ea17377bd32d8b1f67c7cce19 |
| 0x797334e67c79a0421874753096d29cbfab08bbe7 | T2 | split_pull | verified contract |  | RCHAutomatorBase | split_pull 0x39484ef214c9aff5764f64c13e5bb5151ab44d90f2296d6e670960c2098b2156 |

## Run stats

```
{
 "blocks": 321,
 "d2_candidates": 596,
 "d2_confirmed": 6,
 "d3_candidates": 319,
 "d3_confirmed": 0,
 "d8_candidates": 914,
 "d8_confirmed": 102,
 "d8_truncated": 0,
 "tx_lookups": 0,
 "code_lookups": 2546,
 "nonce_lookups": 1094,
 "rpc_calls": 992,
 "rpc_errors": 0,
 "etherscan_calls": 0,
 "elapsed_sec": 176
}
```
