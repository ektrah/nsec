using System;
using NSec.Cryptography;
using Xunit;

namespace NSec.Tests.Algorithms
{
    public static class HkdfSha256Tests
    {
        private const string s_prkForEmpty =
            "b613679a0814d9ec772f95d778c35fc5ff1697c493715653c6c712144292c5ad";

        // unverified
        private const string s_outputForEmpty =
            "eb70f01dede9afafa449eee1b1286504e1f62388b3f7dd4f956697b0e828fe18" +
            "1e59c2ec0fe6e7e7ac2613b6ab65342a83379969da234240cded3777914db907" +
            "5568c74fdb8fc92331d5c59e1e2dd77a8c2c63aba7cf2d3457f8ee8620462f8a" +
            "d77a798b94238ff3092304585bda6c1581d3f9e758802ad482422fdb555604d5" +
            "89ab88b2079a075576ed7ca6e6e17502db3467112a4d96bd360ad12e30a3772e" +
            "0fa76c13ebfa95dad91397d243f35b2305ed7cc2dbd84c80b8df4aee2fa91d51" +
            "4b6d86c288c51bc60d4f3873b77a9b5dd6c2fef654d7b93e5326251ad923a887" +
            "efe6d45845c429ada72532af834137ad3bedd385bb7341b138d68a2e77d54711" +
            "3262e2db7c1c9610c48fe0d1cdca59d4630dc2724ac0cb31d621805bc006fbe9" +
            "0df89c35239ab1a43c42b2ba08116fe7c9f7030e24253cfb9c12fbb17de12f27" +
            "b93791e88de4c54a368391a9e5658f1e6cb8d033bfa0ab14c2508eb0c8918ab1" +
            "35ad25231d072da928ea5ea7996b64691c5f3bb17dca8a29122ac941c9279685" +
            "c7ef13d4c41851fb593dcbf69e03334cc07056d3820df6c4c4f18be8f54db156" +
            "f55ef0811aefe859fc8e5fcb7ffb632e255a7225744823230b93018746eabce0" +
            "5255521a0d30b6edc313547af56f21f26ae942e9d69b644cdd1e85ca487ea794" +
            "6fc10956be75c0c15c618bad29066f7ae85f44a2663b2085811fd44c8c5671ca" +
            "04a715bf2e7a592d55541790fb21a3015c6789df8edf43584d9a6f5f28662a46" +
            "ef35fe690519747067b7e099f28616b7da326fa71041af29739d161b37b14dd4" +
            "7b4f2575d166153ef3895c7c57c4262625ad565074fb217ba6d81a29e48867a5" +
            "0ac7be924b0a4a6c8b40ea487696fe1297bf1261790bc1b041eef7a1d03fce68" +
            "9f58be028918e87213efc12f9dee289a6a7db814433f4ed95ffc05f7b1087cda" +
            "b29728ce5c6371c827f69c39887e18ba0527e1c8ed48b20761a1828140b3690d" +
            "48b1c93d3ba2a515cd25a436926e7e6915bf428885f886b3c2414e7c01d053a1" +
            "2e07400f0257d92c6c1f3d2a26e3999869ca16b61e2a74d11a2b1705fc79c457" +
            "163c265768e995b2ec5b7aa51d4c74ce2fb9957feefbe0c085db1a0e5dcf6cf0" +
            "93432b0ee19bb0200b441752f5ad4a7e75017eee3539fc2ca5f595aad0f5c275" +
            "0da5dadbde1ae9d613a86fb2b38e8aa970bf4dc9b089692977f73bad3d9ea6e2" +
            "50034243aab04ff24963bb16ac33c0200244959800b269f03910d4a4144f240f" +
            "6bdf05b6dc82d6a8108eef5e2ea979b8f5d2c5ac89583d0972b845aaf9f14154" +
            "e83f4f0397057483220430ceb64ac4221893ee9ed51785bd7c09a3134897319d" +
            "7507d1e27f76a20db1828623f31fb802990f8034a26140a23bda0715096ff52f" +
            "a225f6e916fa7c8a8558077cc4fefd8962f097b8722611019257ef7cc63be449" +
            "ff5b8af8c2a170c9a64700f917bcfd47875f24c6d3282908aaae663e9511bc9a" +
            "c763314e9c909f73b13cb590eb9a7f1efef469410fc87701e3ed37c2a983b5d7" +
            "a8b0b17742b2f6532eaf59717ce35cb4c93b64085bf261ebf6af4ba11eb1ee77" +
            "46e81e36173e297d43f7680a5d3756a44dba546e117de1a1ace485339e1e3f3f" +
            "2a4f0d18fcd44b68b3dbdf7ea79813ba7e39327e849dab4684bf5a4e64b08549" +
            "f6e903965fe0b266499fd3bb38b24d50b741b1647ff824dd689610c5493e936c" +
            "c1ff0c1a61829c9cb137f9615e10e1d4d81751834825940a7b3329054d52efc0" +
            "e6cac971c9224cbf23f317237d5b1dec0266e9461d3a946a3a2c82ff25a0c344" +
            "ca68d5567e350015fc82b5a7f6ee3b14744f0fedb6165d9b43edcddeddf9e80a" +
            "34b2d1ffcb4617b921de86ebded96eabc555990371abd05074d7b132666257df" +
            "ffe1a867948fca51cc84e857fadfc5e295bf1a5036065ed3b89332731fe2e636" +
            "e9cf7dded8450751b3ca7786bc6afee62d91b03ba3bb6aa474df7cfdcddc4d8e" +
            "5712446e9f86d5c6e094374a2a8a84b05d4dc4b8cae00bdf1311fc1726274203" +
            "3dc519f3fc0a40f83501ef7baf4e14866908e8b017d692e63a00e0172d83de1c" +
            "89bb677bf5ed31ae596ec0f75fa441794be7d03ede068671e5182abd5a8b5817" +
            "7eac1a98e17876babad661bb2630a8a8f695ff62a9caadc5f9e80c49aa415d77" +
            "7b30aaa6ce88b3cc660c829f4b15139baec114ef3295719a9febd9cace9f4c78" +
            "89baa171d7737bb3eeecbbe98b5a8fb924fbc6b8bce9635eafede132c54471f4" +
            "0bf1d84c392161d549a3e9540ae607667a162d1192d73ed5c5058379092050c7" +
            "23ff5d52f571f47f51feb4f230a5c87dd5b5d72b5a6287625a14af52b4708fec" +
            "bf30a4dbb867336672a0837688775c64b5dfbb00809cf840b4506508dd0206bd" +
            "0e31eca1ea3d53ba19fa0e07aea0af131a70b36bd3463032a83764644d64809c" +
            "86f2d6b0a5554618559faacacc4923217307086d6d750f6c24de97547ce4fdc0" +
            "ea0ea7ea790ef774ee1156aa0a1adf2de928cc03e308ceff6ad629a21cad2f65" +
            "d6db55c1a1fc7ee3f3ddf4c729650483a01f4a129b7b9f3f28ebf071c13321d7" +
            "d0bbbc896eed27dd0d07369c5b37fe99ce37183169ba7d51f19790719eb8d27d" +
            "23a3b9d4577bee0c1517b0872cb76c3c82ec07bcfbe4805ff50eeb5cddecd750" +
            "04ba0aca3b9e7731d4dfbb5fa70cb0ef040350fa36c325fcf976dcd4dafe03f0" +
            "c2cdd1e22200d5745c2c7a6958a5ced67773eaecd5dc72d7e848336d6394cf92" +
            "487319f8144cd443d5773ab2c8edfe837feb9f30cc550eb4f0d44fbf57c7ad56" +
            "81e0ee6ad9a249e5cdabafc420238d6b40ca2e251f58587432aeb592ceb66e9e" +
            "0a75fec3af0a45151948b0a786a6f79ff7127d57ae522a83605f79fa0688a126" +
            "0612c47a5300076a708ae8d8272b14ffc94c3f2d09f9074348ca06d81cb38fc9" +
            "dd04a0c1f939f966ad8576e5ec97e03a902b3d87fbaf6e8052b61dfa9b799bc8" +
            "ce2be861c311ac8106c0f4f8096a6d3466067370da6a9bdb01615c20f1567b28" +
            "f320f6093e25c01d9483fcdc47128fc6f1b8f3dded19315298a33f4112af3a02" +
            "b513da91819f747ec3b55345339d1a41fdc524b0fc80b0391be5a097a8fd3454" +
            "c5f8fa78824cc97873cdb54ab64ce546805f740cd42e1df96613338629779cb3" +
            "5e34148a88bc2c236358be8fda940c536798fb9b5f01d29a7b970f27bd0105aa" +
            "515af7569da2c24ccf27d8d3df97f65abe2538132039d0da90cbab346f87cadc" +
            "f606e49863dfe0127211f0894d5d65c4e382d6f4833bed6f9f29bcd9d1dfea11" +
            "c45e7b75046f714fd03dd37906fe7e63919a3a351df1d9183f1ed1d97ea99b65" +
            "f88838db761726c3259c4840f770241dea59602df98d2ce2c18e6e2919014f82" +
            "c16c3d8f969aa7dc48187e3987e8aa814d3d333b691cb3e0edbca71abb819c30" +
            "84b92cea0d027d660c072d1875a1c029ccd7d19a50aabea1a30ef4a5838b3376" +
            "36a7f397a9431376b7792027ad45358411ec0e15edc1777da587461a983787b6" +
            "7a96636257354e6876c2337b78ce73190496c0397f2120f4f350bfe75892d191" +
            "a7bad55f34bb2720124bfb519891177963e431c41b53e6bb072919e540377fca" +
            "ccbd1553b0b712d4dd7d830289962a3d57a91a5b13b3201ae3871df3d30b3e69" +
            "4f5c2cb8e2fd58b510e9ccb74ad660fa4eab57fd752032d6ca1dfecb8660dc8c" +
            "38752f58657848278d7b64257eade31d533e51115bbab34562f62a400ddec8a0" +
            "24f9aab76e96c049cccf972ace463b78ba5dc7bce543d15b22d8586b76aefd9c" +
            "fef12ac118dbf8d11d0eaed7cffe0148bddbcc2c126ae70c44d9873bac25bfd6" +
            "761ef1a7704b08f226333ea1dbef185ea39ae4ee6ffff2d90c2b0514a8011909" +
            "8146e8629b0fc2eff002da45f3ab6dca041ca7d07f9e573bed918539862cd58f" +
            "02b88d51de8c816ad3cd5717b6493284a3b09e34ae64fc54b2ba568b4ef95834" +
            "e9417b3b582f21aa28db211c33b9df77cf761c54d1ab2db573136369aded3a44" +
            "466eaac59000c466df7d28bfba8178c07424cd651fc7b28f32a8e2de72d48d08" +
            "f351ae8673389a08375978486759a764c332315b60bd07b4e9d76fdd8f7fd048" +
            "61063c6bab78bba423464f57a83cf1125b42adf26d2656225eed95e25ae7532d" +
            "a0f6588c2ffe658e3fe31a385f5408aedc51ed39e7ced048769e2e973f1a7e99" +
            "ac7153e4581494ee105650b2cfbf9f7c9145d860f6b14994a3595a7cf71fec30" +
            "c9f11a79d791406c601df6fe5f2a68ffa6ab728d4ddb1888ce4991ca44077b01" +
            "7ecf68b6ff65c8a5baac512435b339c58b548d3e35ffabd25fcc2dfe5479b9f4" +
            "3b3e4e6b055847e37211e0be70a886c90976d954a1f9da754a6e99fab1d1beb9" +
            "f5a4e11e462c91d1e70c2c70dffc0cc8706fb45d06d8124e6cd20b3446395b0e" +
            "e8e17ee3f39e97208765b2ac39becf12bea12327dac15007a91032fe412f7e51" +
            "a0e22c99f95f6ce73e4d94149bb37bf424ac25d37ff9b3a75e80400918d145b4" +
            "9ca1b67aab3c03803c578b585e160f6dc501ca160b58df45de9cb2667538ad84" +
            "c8b3be6624cf0434f4b74ad9b7e2d9090cb90260c7028e92c21d2a4556aa8fef" +
            "60cd8711152d52e79e506987e2758c701a64cbd61cd85526aecbaf40d91ebd75" +
            "0698d0add54e6ae9c2dc4dd36c42e093f142588d99f3bb30688f587250d48f62" +
            "aa7c0b067086d88d4a7ac807ff8371af3334b11211b9af979841787acd846dae" +
            "5d6b1f9947caa86c821920db0f8373bb53aad4b6202462a1fe664f2f15bd756e" +
            "39c6ee44d78cf4c3501809428d4b5bdb5e8be369bd31bae19685db283ceb2a1d" +
            "dd348ca61203028b009735c3b97c7df6b55bdf745c4f84a0a2594c02842619dc" +
            "d210586dda9fe6b1637584512365dba9a9f9e9c8401a541d97f951053296ba05" +
            "ec5f955e380fc7da3fbe7c9e918f1fc515cba6f48b658d8045e56aa92d2f02d6" +
            "c5e22880d8c95e8f2870597eb3cb48b6655c60d5fb92577d981b444c6433c22d" +
            "931c014e9b7a9627a84f6399a9bb61099263f98ae927439eca748cda5e0effed" +
            "8639847bb8698c7c02ae21fc6913d26251870c7fe6aea9f82507bf76bddb6b13" +
            "12d349f6f64175740160b10f1e39f3f366cb48ae8b5130d7ea1e2e1b564f2d9b" +
            "820453beb97346034a0425c81b69c5cc699442345952978aeeef39d734cdf110" +
            "55d7461686c0acee68cc432781554a8f6c093c8a47223b59a0e239f81b1506ce" +
            "1a9a0945c0316b7033949fb3f98216b00310771adebafcafd76f71707cf181a5" +
            "74d86cbd7c55431e765db1dc77b61161d4e31763b0104442a38799204cf7b70a" +
            "578885c7e587eef6a43d009f0635cb5393f1753e905038d63c056afb23deafbf" +
            "15feab7789f8c37ac963d3e7f5fa9c8480b6dcf7905f1fda8b21e8d0302d1f01" +
            "d6fafc5d910405eaa780e633af68130fae19bc46acc0be8c0c2dfc2305ff9a36" +
            "241fb704297a182dfc2c1bc122c655902335f75f5cb27e457022154c0ba61327" +
            "e7f296ba34173381996e0e1b257c47702a6b8d407d9f8b12ddf5ca81ecf30b5f" +
            "d3050190042703e6822c95ac58457e7b523f66099e834796323961df01043ee8" +
            "4972f6f748d4081201d5510735c67c82e6e43d48bc3b483b8b3d4830139477ff" +
            "4e9974aa712c9fecc491b11c11bf30b1884b75ada9c2fd40ac40cec0c0397787" +
            "ec330608a1340d782854c271c7723b21738ecb1f51391144f9dcbc70ad6c6587" +
            "9013fa5407bb4f7d4af222d47eaf1652b0fac38629f81a929f9444ce9bc15445" +
            "7adfbc37585f275f475a336799e4e4eff5931037fcdee8692de4b1a773030a3a" +
            "b5ceaf77dbe5a1e1aa760d048c6fa096e76fd64accb1ef6bdce32f0d2b0844e7" +
            "9441b2250a37e39c51189be672886890f7a4cec7ab5dbb1937b36294d2972d16" +
            "6c7189cb20b4e3876dc0d7dc810b79064183deb5f0cf5bdd7cf1646ed2c281d2" +
            "73d447339cfd2f320ef4d56a4713a6e898f190df698c16c4e3ad0dd7854e7c19" +
            "51ee385cef896641a1d0ddf18afb2160c4c811ea576ac9fc73937763f66221a5" +
            "630eba26254b8796b80d467e71a37c9c3113f0643356069041c4f2201ebbfc3b" +
            "272c2813deefd1f7751bd1eea70b12fe9c95711c489ced326be19e699bc889ea" +
            "fdee7396f7a89ce24dfb0ad225f466f19c1cd2bb3863fafbc6482fcb46762331" +
            "2a1ccaee0bdc9fe8b736926b4ad33e53119af47bd2c421eff6306395dbf32105" +
            "bcb18a169bb0cea8767d5198cd9e208ce9f85f2d1f1d4bd66754aab8f4647d47" +
            "f84ff6f445a7df5788db52d2725d07b241ae4ffc95f949a46fe60e336aad5922" +
            "2f7f597084db8ca824fa1c5f0cd560f62d498c34a5cda933f44471d9ec6495a8" +
            "aaee55937e0c8d10984a28f9071437768936655be6d7f45d97c9351ecc092366" +
            "a2049a737b00a2118750fe52a317c418b83a5183b79239ecb7a8525af9065a56" +
            "9d0f0f4d396857a560c6e17cf89a2640c7d714f6430e03c63087afa52549431c" +
            "1684d65179774ce2f9d2d9014a8e064300f4228ba7e8460661e6378c7f032f1e" +
            "5cfee69b7f6874beabaaa5021f95c716cf6265e78bda34cb3001aa2f3812046d" +
            "442e8ddf2ef2008c6573da085fd497a01ee40aacc640a8093e79e0135b429fc4" +
            "af80b0a08362666ca2e10b9b1dc91d3692000079d1734e4a4a553aff3e36f1f0" +
            "f1b9d491ad13c25448b0dfe46766f5de46dc227553bdca808d88c44ddfbe4831" +
            "59d569326896e57f2a3c1e5ea6edcf5093717d1821862478d693b87f7deef7d6" +
            "db3b3f77fc54d355fdb5c5cd27dffa7104cdea0710b1b075145c8447cf0199b3" +
            "b69c746ec56957ee7ed630a7951e7b9a2dc284270f7f7db5b2994fc50629841b" +
            "e957c8c623ec7263fd68acfe53c5bc275e402cc1341ad31fdb31ecaed65dcade" +
            "7353ccf7c855ef71f92f625901617a70ab8b854b3d26b35006e9ed8c9886ed04" +
            "a74a8e749654469eb77d9185e5b1871af38be067e3a70fe3dcda45df4dd5f159" +
            "4e4bcfc80f24bebdac8344816ebabca60b16f5235464b7f67918bc6ff76304e1" +
            "b4616a6671fb360237b54cfd894927752d87cb1d3b4e5e1a152e72b647f05992" +
            "76d8ff8883d9d551f9472b457ed430a5b36bbf41a3ea36b9ccf8a79983924383" +
            "efa7a5a83a4765fe4aefe0576bb74b307828df51952c91a5e2834333940084a5" +
            "adc71ebe37c8d876eb21d1b337ca66ec41ec9606ccb2cf8252bd7a38302f9147" +
            "dea0fe4b3a5add75d6518b6c1b1eee2bf57bb17dd64b9a01928c1311a0cc3db2" +
            "bdbf2bcda88cbdeb8d45fbf2e39626baf0798b600bfab3cba2a9e97a11e30b65" +
            "8943a045cbddc64ffd11187429de7bacde43b34b098c673472701f1176d23263" +
            "ac8244337d5f5c16f640dfed98fdab1a5b2d57efd3fbb52093689c5d57e0c6db" +
            "c18546e011d176aed23820623013db6a319768f5ac5c4e7d3b377772a8bc7a9a" +
            "526f8b58aab640725fee0f4c323ad9d92aa8330b424fa7899eeb4f3835d23d74" +
            "3e449023473e6ffe8710cfc169fee62adeeb120cfe77a53fa2514a4f0199315c" +
            "614b5582c0160a841cce1cadd4dd9467156132e36e308d53d9edb131c2a0e10e" +
            "1668fdc5141a673baa2f6cd474e46dec3a72ebd72488fa9611b7084a1e42cc96" +
            "d9c12f30b28aa0e4a841895c58c186b97d70b3cfee4d50000888b7799aedf743" +
            "0bf6b1b940b9a61bc4b4b8908d28a85f2d101aaa43df1d95a46e06b40749173c" +
            "66a5796c31e6b5727d5d7e01bbecd96b9df13c2cebab0df7e87b0d904dd48e17" +
            "a7fea0a5da5136d076936abf51ee152abb8da18d55b8a6fa8a377dba3d5cad84" +
            "1597be94b48da4babb790f9d62e94308947102a1498b35e4175f72377667b074" +
            "c0243b12c058b1e64887d5a5f357f60f7cdea0fe09f82dbb63e6b684b41e0ffa" +
            "b5fc7e7e32b0f4e1767ea81ac0f315e166bdda030ea36cbff05ee116568d1ab0" +
            "92781e53e2b6e6ac40a7d8f3312d629e48dcc8a2268f2ca9e6dc5d44f82c8f3f" +
            "42bb300d84ae433820d57512940e087638294a582fdb5db4fb6b470b8863a44c" +
            "8f0d0bf4fb802201438965db694776bb6e6f24b3218f4a48ec049c2a9436e572" +
            "e4a3d5b491829778854b198e1167f34577cf436a77e6fc1baff380618f8c2a1a" +
            "e7840370ada35428169d94b9e80fbf9dd039b36ffa26fde56cf59b5699134ec2" +
            "a337adb3cf422496c8ab3e993d6f9dd1b78ab6a33185c6dcf19ec4e09b1dc116" +
            "9b0bdcac4b831890c7282849311c6006e2d62bbf72345789d497a5bf0a57b1ff" +
            "aa11bdf4db75fcaacdb895639d58740e559818a5c7804cc170f0bdfb5f777a62" +
            "2fc397974ee9061a0262d210224037feb8ae2565dc59b439b8d8287ac70e1257" +
            "67cecf20c74fe88755b96235b466b2e7f32e3fd2539657a5bafa83547a412407" +
            "c4f32e1e01750f1d3498574a34cc1f9c87edde2ee8751ba04a4fabb81e740726" +
            "638764221c29eb9c32c0b9366e6ca73a9c55d75bf9434035b622567187482684" +
            "31750be3a784169e7e4082a020c6f40324fdbc977220f77c510615ae5f129bbc" +
            "dca3b800ebe0d01e3267e899dbccced0946b62fe60083de2f86164c7c4a37c56" +
            "02ef50eb14476aa3ec96f055a1253cbcd73d93766b64a55486fbeb0029e5480d" +
            "535a5ca2eef2473602ed643ff02f05f00823991d830f2554fe5813265bf9ad6d" +
            "bbd956ff63c2496b947da4c6e1e6dd6bef9346f1840a378c94f92ece94c7973c" +
            "8a26e7963bf47dfe5cbba129807efbca9ddab3cd92684271176dea24f6b501f2" +
            "491e0317c8255c2a1f7c20647f7507c85a7a7569c1822c64e79d3d3ecbab6110" +
            "f95016315f9cb75fbff2a2b6b7a09c7c27a26c0b5eb5a1e6d71d9cda8061f9e8" +
            "39ce0172bc76ddf1d36f5fe7c88676ec6fc9da09628706b6ad62fe98f4a70180" +
            "997ac64f8565d567aee329fd8c6dda07048e26bed872b5726edd3d8c6c1dd674" +
            "6d3523b4bf2f15b1fb0a0dfe3d7495eaf080c72db76508f936879d83f7d79a4a" +
            "31a31e2c16f1d9cfe2ff174a695e16972a8d76b0ee9ba45e876b0896cb5cc16a" +
            "d82b6cbaa83533aad9fb6085343fc841c964d7c29a8c5d993981d9d971f3f4e2" +
            "c06d6635d0815a6b1134185073d26d91d63317ffe719f12b7d57fd95db09f2df" +
            "1c6b8015c85506ae674c25cca201c73e5eb48621fa213d5ba546ab5bc8d0f37e" +
            "c75b2179f5d28634d9ad6fe2ad8daee5d6d0318d37435b5be8d0135e20aded95" +
            "aa81a612262cdf24c6fa41b3c5446fb08d6643031c56126b6dad48641c67825e" +
            "4331e3a1ca88b400189d19a2d940537c07a9bad3cba6c3afdab0a7877e5e2e37" +
            "5b44a4bb005395137d3e7d735865241b616e9ced1a7ce2145a1e65709ffc24f8" +
            "6ab70d375a713069ab5cbe781dd3a8755135031c6c8dcf7bb9c2af8142ccadf2" +
            "b387951304c79de0fbe99baa519ab844f5878f5419b6c98523ae6290858a7789" +
            "fc3d39e79fac53f721355e4bb27d273f11b9972ede30b42eb7668c4715405e24" +
            "594702eecf0b9db00c37abe1e3ddc6f3b9d1e579a3d7de4d982720a02fb52174" +
            "105f971eda15e1c9a8912bffdaf70214893ee7eaf6635874fa633885dde419d1" +
            "24982675705f34b7778cb6e84a3b3c48fb39f741a241353ce3c290385ea1a12d" +
            "db0c1f8fee7dfcf4022c631346ef9679638ffb9be83ba1f5f1f9c0fdc240b2b0" +
            "d86edfde8a1d8965ad04cd7a27ea17983010c1a724e0b1a6d895a674b6081c48" +
            "17ee7a2b86e9d44417cf42040379b3a6dcf7bf9d1d43a441df8cb53b69e475ac" +
            "b9d6e38980db01d3b9359e8111e83b1053bb8d9e6e8d82479dcc174e49fe3b2a" +
            "4ca21c6dec70154a558e4cebf785a0e6f95dca0548a02d4d33bf1b581c41ee4e" +
            "9ca87109bc90dd40992b93542897d5fa99b3caded8fec936a78d83676a4e12cd" +
            "1215237886ca1fad9a0327bdc0cff9a09c0d554ba00f7ef46769c16d9cb9530b" +
            "2f45b3da63f5bfecadfbdb1b494ba863d560c4b49c0988ca889a12c50df8044f" +
            "50660bb544d4f5aae1b295d2fbd5ceb1bbbaa7864787eebfd6f9d46e18b154a4" +
            "789e008ed16e459d0955e741a139dc14f686b5d75bf75216175ac373c90f6ee6" +
            "184b47e8d5135ce7d6a74e4f4359337f945d84aa344c9765fdccb13d93205d92" +
            "fa567fcb2128e6d93bc44c28aaace017c05ff8775d61879fff5ebbe0d7c8df14" +
            "523f7d9fead464dc4ec2ef01f82274aff6da8b51a23e0eb279c76d08e0d08c4d" +
            "ac5998800388cded1fc5cfb182d67f9f040ae0540498de28da8e87e8992bbcf7" +
            "eca49818b7c89b285786190a21f27e566147fffe0d59538baedbdc0f223a554e" +
            "c939e48874c6748e0ee64b1af90394815326f008fbd2d341daad587c36c383a3" +
            "7eda3f186f3b5e5e734866af6892a5939b14c80378867ba9872c4a06692eb24f" +
            "6d22d0c0ac0ab363702a06854df05372ca3392b1f8ed8e83eb7d468057284f62" +
            "89dbd6b06b435d5ab3e670483024383138ce11ec5dcb8b3f9eee914bc3779cb5" +
            "240d1ee4648698d25a074e4b70244d601e542fa3731dfa7c79c4f5fbc0a9c9b3" +
            "16450342a8b0260607be5e134782afcc4db8c9e45bfbf18968f581d03148a15b" +
            "f203a668f557567bd05b72bb982abcb929d3bb0c72042f53a01dfb7361777edd" +
            "3d8511408d1de9cbc65f1461c7993ba2dd686ab3f38923c480f45fe79f3dfda0" +
            "6747d74342c4b5c26fd9ad0865c6b57bdaedbb044844b60b76b357ae719ea23a" +
            "60c7e0b51c0fc06ece311335bb16060637313263d68d5e4cf152c717e9d65386" +
            "903efa1194196f38e093ea4b595ca0dce6d67d8e9bb79dda12d8ac9cce957898" +
            "c6c59bba22db8a5d193b9ffb785ff0e2eb682ff588654144500e0a30479604a2" +
            "860b8399342d0010c0e136c9441c3ac96375da9037098fff094fc0a0d807a35c" +
            "bd1878c0e5768ed09c1e122d6b5231ec4e37eea6a357af1d4fec247de6060e39" +
            "a709ba9877f70b185fcf01ff5f2cf8eec09707369d511390810c69f865e53e72" +
            "4cc2c321df00680225ae9687e82d89524e363026d53d78ab63f599f2ad2ae7ca" +
            "bd37a2bf63fd16f11203fbc056e2cad470761f5acd29c78c25ca14eff7fc9548" +
            "d816dd63e22300a92a7e3fb73c04c6062e476f7948e7b8251f5205ccae7163a4" +
            "ba48595f6002f6b43156d4ece76d60d7bba0883510ea61375a4c50349f717338" +
            "69778e41df56063730b69f599b8592a8144e119cb266a74ad59351ac0487243a" +
            "a720a0e9759957bdb84a17fafbf14b64b955182e9fdbd1577276064adb03eb9e" +
            "cf7fc220a306ee29927a08773a288a53fc399cbf1a60b91888fcc3a2e4a040c2" +
            "fc174848263de5e6f0372b73d6f3f8f4a1e8139e76d1402fc40c33bd3475a31c" +
            "bf9bb8ce74cdf96c20c3c5b01f17a87be43f855f976bb1180d3e52df9f273eab" +
            "832b93a58736568ad1f835164029df949187bff7d59b4947394fc4e8e695857e" +
            "fb413d46f980262ab3869cfcdf966f7cf0f0012b70ce20a0603102a495b34a43" +
            "d088fc3911508c67b985be209d5e5720b9e9d4d98c145952a1aa4362caf53fce";

        #region Properties

        [Fact]
        public static void HkdfProperties()
        {
            var a = KeyDerivationAlgorithm.HkdfSha256;

            Assert.True(a.PseudorandomKeySize > 0);
            Assert.True(a.MaxCount > 0);
        }

        [Fact]
        public static void Properties()
        {
            var a = KeyDerivationAlgorithm.HkdfSha256;

            Assert.Equal(8160, a.MaxCount);
            Assert.Equal(32, a.PseudorandomKeySize);
            Assert.True(a.SupportsSalt);
        }

        #endregion

        #region Extract #1

        [Fact]
        public static void ExtractWithNullSecret()
        {
            var a = KeyDerivationAlgorithm.HkdfSha256;

            Assert.Throws<ArgumentNullException>("sharedSecret", () => a.Extract(null!, ReadOnlySpan<byte>.Empty));
        }

        [Fact]
        public static void ExtractWithEmptySalt()
        {
            const int HashLen = 256 / 8;

            var a = KeyDerivationAlgorithm.HkdfSha256;

            using var s = SharedSecret.Import(ReadOnlySpan<byte>.Empty);

            var expected = a.Extract(s, new byte[HashLen]);
            var actual = a.Extract(s, ReadOnlySpan<byte>.Empty);

            Assert.Equal(expected, actual);
        }

        [Fact]
        public static void ExtractSuccess()
        {
            var a = KeyDerivationAlgorithm.HkdfSha256;

            using var s = SharedSecret.Import(ReadOnlySpan<byte>.Empty);

            var expected = s_prkForEmpty.DecodeHex();
            var actual = a.Extract(s, ReadOnlySpan<byte>.Empty);

            Assert.Equal(expected, actual);
            Assert.Equal(a.PseudorandomKeySize, actual.Length);
        }

        #endregion

        #region Extract #2

        [Fact]
        public static void ExtractWithSpanWithNullSecret()
        {
            var a = KeyDerivationAlgorithm.HkdfSha256;

            Assert.Throws<ArgumentNullException>("sharedSecret", () => a.Extract(null!, ReadOnlySpan<byte>.Empty, Span<byte>.Empty));
        }

        [Fact]
        public static void ExtractWithSpanTooShort()
        {
            var a = KeyDerivationAlgorithm.HkdfSha256;

            using var s = SharedSecret.Import(ReadOnlySpan<byte>.Empty);

            Assert.Throws<ArgumentException>("pseudorandomKey", () => a.Extract(s, ReadOnlySpan<byte>.Empty, new byte[a.PseudorandomKeySize - 1]));
        }

        [Fact]
        public static void ExtractWithSpanTooLong()
        {
            var a = KeyDerivationAlgorithm.HkdfSha256;

            using var s = SharedSecret.Import(ReadOnlySpan<byte>.Empty);

            Assert.Throws<ArgumentException>("pseudorandomKey", () => a.Extract(s, ReadOnlySpan<byte>.Empty, new byte[a.PseudorandomKeySize + 1]));
        }

        [Fact]
        public static void ExtractWithSpanWithEmptySalt()
        {
            const int HashLen = 256 / 8;

            var a = KeyDerivationAlgorithm.HkdfSha256;

            using var s = SharedSecret.Import(ReadOnlySpan<byte>.Empty);

            var expected = new byte[a.PseudorandomKeySize];
            var actual = new byte[expected.Length];

            a.Extract(s, new byte[HashLen], expected);
            a.Extract(s, ReadOnlySpan<byte>.Empty, actual);

            Assert.Equal(expected, actual);
        }

        [Fact]
        public static void ExtractWithSpanWithSaltOverlapping()
        {
            var a = KeyDerivationAlgorithm.HkdfSha256;

            using var s = SharedSecret.Import(ReadOnlySpan<byte>.Empty);

            var expected = new byte[a.PseudorandomKeySize];
            var actual = Utilities.RandomBytes.Slice(0, a.PseudorandomKeySize).ToArray();

            a.Extract(s, actual, expected);
            a.Extract(s, actual, actual);

            Assert.Equal(expected, actual);
        }

        [Fact]
        public static void ExtractWithSpanSuccess()
        {
            var a = KeyDerivationAlgorithm.HkdfSha256;

            using var s = SharedSecret.Import(ReadOnlySpan<byte>.Empty);

            var expected = s_prkForEmpty.DecodeHex();
            var actual = new byte[expected.Length];

            a.Extract(s, ReadOnlySpan<byte>.Empty, actual);

            Assert.Equal(expected, actual);
        }

        #endregion

        #region Expand #1

        [Fact]
        public static void ExpandWithCountWithPrkTooShort()
        {
            var a = KeyDerivationAlgorithm.HkdfSha256;

            Assert.Throws<ArgumentException>("pseudorandomKey", () => a.Expand(new byte[a.PseudorandomKeySize - 1], ReadOnlySpan<byte>.Empty, 0));
        }

        [Fact]
        public static void ExpandWithNegativeCount()
        {
            var a = KeyDerivationAlgorithm.HkdfSha256;

            Assert.Throws<ArgumentOutOfRangeException>("count", () => a.Expand(s_prkForEmpty.DecodeHex(), ReadOnlySpan<byte>.Empty, -1));
        }

        [Fact]
        public static void ExpandWithCountTooLarge()
        {
            var a = KeyDerivationAlgorithm.HkdfSha256;

            Assert.Throws<ArgumentOutOfRangeException>("count", () => a.Expand(s_prkForEmpty.DecodeHex(), ReadOnlySpan<byte>.Empty, a.MaxCount + 1));
        }

        [Theory]
        [InlineData(0)]
        [InlineData(1)]
        [InlineData(2)]
        [InlineData(17)]
        [InlineData(31)]
        [InlineData(32)]
        [InlineData(63)]
        [InlineData(64)]
        [InlineData(100)]
        public static void ExpandWithCountSuccess(int count)
        {
            var a = KeyDerivationAlgorithm.HkdfSha256;

            var expected = s_outputForEmpty.DecodeHex().Substring(0, count);
            var actual = a.Expand(s_prkForEmpty.DecodeHex(), ReadOnlySpan<byte>.Empty, count);

            Assert.NotNull(actual);
            Assert.Equal(expected, actual);
            Assert.Equal(count, actual.Length);
        }

        [Fact]
        public static void ExpandWithMaxCount()
        {
            var a = KeyDerivationAlgorithm.HkdfSha256;

            var expected = s_outputForEmpty.DecodeHex();
            var actual = a.Expand(s_prkForEmpty.DecodeHex(), ReadOnlySpan<byte>.Empty, a.MaxCount);

            Assert.NotNull(actual);
            Assert.Equal(expected, actual);
            Assert.Equal(a.MaxCount, actual.Length);
        }

        [Fact]
        public static void ExpandWithCountWithLongPrk()
        {
            var a = KeyDerivationAlgorithm.HkdfSha256;

            var b = a.Expand((s_prkForEmpty + s_prkForEmpty).DecodeHex(), ReadOnlySpan<byte>.Empty, 256);

            Assert.NotNull(b);
            Assert.Equal(256, b.Length);
        }

        #endregion

        #region Expand #2

        [Fact]
        public static void ExpandWithSpanWithPrkTooShort()
        {
            var a = KeyDerivationAlgorithm.HkdfSha256;

            Assert.Throws<ArgumentException>("pseudorandomKey", () => a.Expand(new byte[a.PseudorandomKeySize - 1], ReadOnlySpan<byte>.Empty, Span<byte>.Empty));
        }

        [Fact]
        public static void ExpandWithSpanTooLarge()
        {
            var a = KeyDerivationAlgorithm.HkdfSha256;

            Assert.Throws<ArgumentException>("bytes", () => a.Expand(s_prkForEmpty.DecodeHex(), ReadOnlySpan<byte>.Empty, new byte[a.MaxCount + 1]));
        }

        [Fact]
        public static void ExpandWithKeyOverlapping()
        {
            var a = KeyDerivationAlgorithm.HkdfSha256;
            var b = new byte[200];

            Assert.Throws<ArgumentException>("bytes", () => a.Expand(b.AsSpan(10, a.PseudorandomKeySize), ReadOnlySpan<byte>.Empty, b.AsSpan(30, 100)));
            Assert.Throws<ArgumentException>("bytes", () => a.Expand(b.AsSpan(30, a.PseudorandomKeySize), ReadOnlySpan<byte>.Empty, b.AsSpan(10, 100)));
        }

        [Fact]
        public static void ExpandWithInfoOverlapping()
        {
            var a = KeyDerivationAlgorithm.HkdfSha256;
            var x = KeyAgreementAlgorithm.X25519;

            using var k = new Key(x);
            using var s = x.Agree(k, k.PublicKey)!;

            var b = new byte[200];

            var prk = a.Extract(s, ReadOnlySpan<byte>.Empty);

            Assert.Throws<ArgumentException>("bytes", () => a.Expand(prk, b.AsSpan(10, 100), b.AsSpan(60, 100)));
            Assert.Throws<ArgumentException>("bytes", () => a.Expand(prk, b.AsSpan(60, 100), b.AsSpan(10, 100)));
        }

        [Theory]
        [InlineData(0)]
        [InlineData(1)]
        [InlineData(2)]
        [InlineData(17)]
        [InlineData(31)]
        [InlineData(32)]
        [InlineData(63)]
        [InlineData(64)]
        [InlineData(100)]
        public static void ExpandWithSpanSuccess(int count)
        {
            var a = KeyDerivationAlgorithm.HkdfSha256;

            var expected = s_outputForEmpty.DecodeHex().Substring(0, count);
            var actual = new byte[count];

            a.Expand(s_prkForEmpty.DecodeHex(), ReadOnlySpan<byte>.Empty, actual);

            Assert.Equal(expected, actual);
        }

        [Fact]
        public static void ExpandWithMaxSpan()
        {
            var a = KeyDerivationAlgorithm.HkdfSha256;

            var expected = s_outputForEmpty.DecodeHex();
            var actual = new byte[a.MaxCount];

            a.Expand(s_prkForEmpty.DecodeHex(), ReadOnlySpan<byte>.Empty, actual);

            Assert.Equal(expected, actual);
        }

        [Fact]
        public static void ExpandWithSpanWithLongPrk()
        {
            var a = KeyDerivationAlgorithm.HkdfSha256;

            var b = new byte[256];

            a.Expand((s_prkForEmpty + s_prkForEmpty).DecodeHex(), ReadOnlySpan<byte>.Empty, b);

            Assert.NotNull(b);
            Assert.Equal(256, b.Length);
        }

        #endregion
    }
}
