import hre from "hardhat";
import * as utils from "./utils";

async function main() {
    // const verifier = "0x81962029F1111F9627486754EF45d0855BB382BC";
    
    // const data = "0x0000000000000000000000000000000000000000000000075272755bc787092400000000000000000000000000000000000000000000000c2f1373ca71f2da050000000000000000000000000000000000000000000000028e082599d78761580000000000000000000000000000000000000000000000000001895322a9850e00000000000000000000000000000000000000000000000982cd8817fafc54c10000000000000000000000000000000000000000000000087000e09e0ebce6f9000000000000000000000000000000000000000000000000cd3d1530491414570000000000000000000000000000000000000000000000000002b2ef7d59590d00000000000000000000000000000000000000000000000c700b37adf770b0a2000000000000000000000000000000000000000000000002398eb6834375065800000000000000000000000000000000000000000000000737d29d1816a9fca20000000000000000000000000000000000000000000000000002e276eae6b8d6000000000000000000000000000000000000000000000002fc4a98a947c0a27400000000000000000000000000000000000000000000000bcfa637395e4ecfb30000000000000000000000000000000000000000000000076f23df3085f67b730000000000000000000000000000000000000000000000000002d42cb574e6d81d7c62d01ed1a9faf7aae0a0a1d485f3b72711b843595a97a51dd4deb1d9488017e44e17fc324e0334fc8416ce2561fa170696679c8072a0130eb8b8568128770968f9ae20ee36aa05451625cb09edeb9cdfabbdec56ac1b2b8d003de90d24cc18f327fd2f3ce3f6846006e30332ac03c094c58ca1b2282ab5a85390e5f1b49403ace759651ca6f4037f7a0541f13b3dc737852505b5fb76086300a2919fcfae14b1559e9d10ede96f24b95a2523e3d737e55fc6f6cc0bb7f7db64ef29cc95a520ab952d2fffe37511df2966f201a6f42f9b80b865aa7397375828503121c82e06d4fdf2329e95b5ea58a67f6ad60b7c5609cc811643935cde2372598c7271bf0fd71270944bf965fec545c10ab4d8ce59187238a69b828084fca1b96f1b057e100bd695cd9810573fe87897e27bfdfacf17cd4993073c40885346a7935120941726d85195d0d7c7ff47518f8d2cc2e2cdab295533b0ffe1a283e07aec34bc15123b00ee7654c3c7668044daf0e539c71116af47f7fc6b22c702df55c6c9509623fad001496b91f9298c1d37782e1744d0cce6dd094e7556d1fa49053a897c060b4c2802843c9bb895e60d6725608daa731a3c1a59c2677aae3e3286cd3d87b31b46be79b67e93fa2c094d5a89401c42e3b1193795267e1b60f83548fd56ebfe2a161097dae7f7dae8b3c0c3982fe5e9182063a782d92c5e3cdc7aef5108ad9500f588354bfad2a51fe43e7d7a6c713aa065f315af45d568129c9d3374a88f932bac602225c903c4bbe6c8a5a8d1962a89e2595b999db2b261bf6ed574d5b1182f7755765b098556e67477c9302ca75472fe70c3dab23b8df9bc52ab0c00e99d02671c3ce347c7fe4cd390535634f0af1141d0ee06c4e83cccbf6132b07c5b7d130ad0e00b84bca79b3282f4d3e3d32ecfd78bcc3c59175374757847259a5fad0d36ef85fda8ba448b4fbbafbe3011066214305a17e561263a5612b0082687821aa7faa7a53f23b30d24e5fc9d0debc77325613b11c847fd0319ec1d6d8ec7102843ca659376cb9860e003b83d97447c01cddc25af72309bfcbaf97d6df115c12e786d20fbf0f377595743855092568c4f074ee074a5ded317b20c61b76c1fbc1650927467bf3a80b37d1db56589f1f41bda2702701359ca181c8f117c96d26c27cb330c2e213f0146575c1b13b4f898ff9a16b4f4b7e20757f5ae35e156d9df0a52ad2549c29d5445fddb7fc1eda23694d45e95dfa824e1692cdcede60441791b2c9e1cf62767e9cf5e7142f833b372365353871c5bc3a2b569c62a1636bbe6281270d993cb788a26d00dbeb6898e66d20ab1fbf4e9b15a0f12e7db90799de406a93b195c4f3551c47d7dcba6554cdcdbb1f6a9feaf3fd0e303ada1a1137fb618ae46746c031590032d660a1e1ebd429dba61222936ff746012912da40195ac0de3b6d005802600ed7b0ea2835303768209ceaa164c3770f20a0b4fc0ace4ef226da54714ece3c8b9433a7f1cd9f4cf833cc3de26d2ed50d3b3900e6b6a9f8b06066e1296894bcbe05d81ef90a1e94fc809f21fc564c3d9ace9787585b8201419e652a20b9428646761d57848845ce1b279b864d13658d880d4d32799e061cc1f0f732a0e522205fa73c00539694c1d2fcdb5a5d0c40aaa0ad9ef379bbed8a326705e2660fe2a1d65dd07c3e11f1cc75a44a6bf476563fb1db09fccfcc5d6ef1c423e6f930a8c30d975436500424390028887e4b9782f998c66dd7204c6e3a20bc3d4b04d644aa4fce2edb95fda6bb32efbffb10a5facfde48a2eebe6f1db302865fe160595b9fabfda4fbe15d18a4a50f8f3bb0c5fbe69c75d5629ff5a06a61b47d748a6c195b42de5e3ce27b964a2641c163a64299a66257c3ad02e8cdb7b2688bda71c4e549d2c3c71e26a37af547f9b7c4027da8698278ca7f0f12bb6d62da0d991e203bd42849c6f33c36d97e84bb571a8713f9d0af0a3e0a9a4bf6b1120ddcdb87ed91abad8818b5d9e034834b3c324c897ea749517eab56ae3c1dfeb0932950813cd031eca211b9bf29d55b262412598ddc26075e4baa529f1d0d21d0a87bf3a715ad65a7f5d9f875bbf836fa16ef578c996f354a694d85b4e2a56a52ef5c4afa813495ba9dd4d370f83d109b15482468d5c9fc16023c580de6aa5842bafd5c295a540a36275a3c7ac70a6cc06db62d51e56faa2a967ef59cc6dec5722e9c6e003976e0eb228a2f6d304582eca2d9b1f9db9b906b80bae2f5888a6260dd7cd392cc6ca96916829455f7ed04bf5782f202208469d17e5c43c69328f182a027a8feab4da0cf3ad90b2e116487b2de34e094d26acebd0e5d4f35f17f98d2ba8d27e90bde91737e4a84fea197890f65ba6f1d0cad625d6a27e2c7e332d81199cfe01e1ad02a0246c46acff70be6b25287d93c2c3be48a6dc60aa3ec32bad2e9cd0d5f5fbe8b3c3b2c302caba2ff892ad57c045232eedb05f7701002bd44522b7cf7586f81eddcefacaa13f5d9828d72203837b48728b699b3feede3b13eb21e3b9ab86d95603dbeb62f5bd98d4ced657be7535e8239d30bdbd112e781e4b14710574b6e7b405b3a91f45ae74e75a7296e8ccb675491b09aca72f02907633173b9a095115f24ccbf787c26b9a6f40e1b1484a44581a31731ac26ae15b5ecd1273c089ed8f8a26256e27f5aa23d3da259135d2322f8e0889db560ce6934f58052d497dfa3596087e3591bc69bcaf97d08fd9a2598df955e2099262a6f09d6a15f8add03a7a22306b38b1cd1d115fe6c14cdf6a2e26e1d5901a8c1704f6176817e5523650b646a91bb152ab50a0ff757171322b9bd68acd7c5e416bc0e577950c68b66c778aa1505d8da525ae2dbc37f1a6222093626abf5f90c13e0362c01811bfdab715e0296abe606e8a858547814dcf849a9742cb1cde7350414c51f49d2a16ac9cb4875584be3653331ff8f8ea6d967750b1f8c5cce1610502c4b9e67208f7cbd669f16820b8f3cec2cb845e54ac485e50472f55db54b2c7d2df477ec82c601a9b132192a719f7433c8045795d46051bfdd364ec3eee43916cabc1c9962c1be209e05ac6cc98000df69cc263a03c17f70cd7cf9551fdc600d146de4d7d264cd19076e9c299fe402b7222dfc659cf5a94f4873244da3e6d9bf8ef8a2a4223639b1077674e8b71b0a48b677a86ca194d68f680381d97ee585e1d9e73941924ad94fc8d8e6b13f3f09340e6d1d45c1a3b84d4a97601f386931f7c66126455206cf8ff7644698dcfef2ae9eca8e8cbe1410ed30e5a25442696af9143ba90a41f5b07983b6f6da3a4b87293031bf44310214d89dfd53cfbae552fab9ac89192083bfcb412ead56860267605fbb112f393bd283ecb2b167a718ae570911315c51425712f161b92cbe6a6011ab7dbb4371c0f0c58eba11780bd1fbd02d11af0f1107003ca02ec8578060bef622fd48612ce8e6d782f337adbf42ae4920f9b02db2772ef98e0beb8b96d18372bacd4e6b87628bc8847f140940a9020f15004b326198643b5509248fe79dd925e79f0cd4c54d59c29606bb68acbfdf92d2ba00b640ecba7bafb05bbc50371c76d20141b6c1ee960f1afe02a601fe202bd09f28ad30c04056d475534cfb14421ad737d0bafc02594e14e2a862574dcd6c29072d7d224be6d3d8ecb80621ac517601aff4cde07a8c01c43a4e218f23701ea41bdae2003babb584d6b45dec6daea4a65613a11b62935fb40c0c1e1ec418709af47c4bd2518c3dcabca74df4751c92a9b23164e35c9b2e2b714ce34e2c21a70138c62f6203621cb67e7a63bef3f188c8d2c7aef2fcc2b92bd395888b2f7e8b64efa03862f9c4ce841104dab4597f56b26d0d2bca88f0e30ac91dc9752bf191d9aa45b030b848b288f342f2024c1908e6324286740a01b1114dd581a3816beebbd99744a2aa17a2d44f00277088b27c5fb196d457fbac5326a32315742dfe6b7e1b7f5e60ce69e74a6aaa86939682678ba25cef38fca8b49d33587a9cc4761a67d3daa740089659410ed8a1847e80f3f5aa6402c5f85a364ae996bb462d72da5cc013a250337ea40870c95cca7eaf8ee877f8ec9fcea432cc836bb9aaf1858488c342fa410a4dc5993836e901e6ec441abf0566957b14f061d3063525e1ce6d666f823fc0e257c614dcafdce1cbb59eb5b65ac425130bb033edd21497038b711db59aa4119ff11794f05ca580067cbc1ee25eae877236d37641d999eadc747b29b285de91c4af3871f7accf084dbc5bcb355aa20d4bd7abcff9c4f527851b32b6a5954572b7dee5155ac332dd80aad7c2338d924131a4c2ec2d2b25511c2fc75fde0267f15095f053a3d964ff8ca7bf68e3833cc69ad5b45b1f4100f6a51c6336ebfbe6a08b498a710e1d99b50c8557d3d6d77a61d1f688a03fd23a05c68d3bdae45bcc40b436a3319d2896b6944509919eb91656d41bec03b59f15f35094a96bc789a351c17107cb0302c3e06a417da17e4e968868d332118ae98e8251f1cd07397721a22a39d3f86cfc15f37f2237ea22d03e86b006311aee523af664ebcaa3a5bd36c1540e4fc444dca85c841f87f4c62f29bc26f831b88d60cbdbb9d19a82079488113c437606cbee307ab0b7e0815e5d13b45b237482fa120f7189822113db8d3df0a926bd17991321deb98c926055c3e1e2b31f40a018c36c2f020ef6e97717a830060a846c70172520ffc902347611ac68a1cd852f2642458109e9717394022551cbee9aa97a7dc13f986ddc7e06cd1f0319b84a5ebac1a3ce2f867cd155207f2272ea70ef21bba18d8662ebaf29f9dbca9b06e30d583ec89a0a358450a5033ed2dd6230d17894c80f00d3ec2fa806052a62f06eb16cd145a573e347196b265302b9d43e54abe3794a5d0c169fa3d72ad477f7c2c9ce918a8a972000e878213362abc1e99699da68ee705d549b12079e11a2787b48ab6f7092c2fe846daeafe2419891705abd040f6d59e3130b744b83747806379ecedc1fa67aa95b3e28333e72f5eceaa9e0ad3125cdb92976c80a5d6ee9b06b3b05c17be7e18254d3ae28f372c4406bba56c90483cd8b2f60fa5cf7dbe89c54077c4fca9225e59bcd55cf1300ed854602e58a26eaec74cfa0a2d19d1a64f1fd41a2ed5d55a19c3377634de9e0bd2a7b6659684c5584ceb0878987292bfe6793178ddc0ab4f6e0355ce752d961886266ce77d7ae0a73b4919485a169a075f6e80f913c72808476a2d253b28f000be80c4c6169b5fd704b34d74ef2e48bf8e2f9327f593663787f145ce8704bd03034577bd0199c7290844b2eb5a5ae5eee4f29322ebf25525fab35c51e464aa0858871c89784a7445f8487f8fc3ac3bdd518ca9485d4b310efd86ddadc81f06"
    
    const verifier = "0xA05d2996A9eD7ec346850166D30e3d82b36ABd19";
    
    const data = "0x000000000000000000000000000000000000000000000004a27903c822133cec0000000000000000000000000000000000000000000000023a2e7b7459c4f39500000000000000000000000000000000000000000000000f468591e2ffd370080000000000000000000000000000000000000000000000000000d7db8f3b2ce20000000000000000000000000000000000000000000000083de1aedd80279c9a00000000000000000000000000000000000000000000000052a95d09cefa2396000000000000000000000000000000000000000000000006214884f862d834280000000000000000000000000000000000000000000000000000a42ee7bafacf0000000000000000000000000000000000000000000000069e874527995e809300000000000000000000000000000000000000000000000936b3c433c6f62d2c00000000000000000000000000000000000000000000000a2048d1a30930c91d0000000000000000000000000000000000000000000000000000a7eaa805164b00000000000000000000000000000000000000000000000be8d87419ff9c5ada000000000000000000000000000000000000000000000001fd8339c88a7da946000000000000000000000000000000000000000000000003cf01b8a9c9df6f790000000000000000000000000000000000000000000000000002a212ae8401f62cc7944a00c6c950e587b7146e3fb802d6faaf3713a5af62bb5f6de31c90febd2cc216187ea67b009b5190f10dda440502bdb11ad9996e0ef417ef88da2c755f083cbb909c3afbc82170a33c004a1a4c92514dfb34c6a2ae36e80b75bd00fb5326dfd92703ed9b3ab6cb73742c6bb7b53715ccb4c8eb6ce3966a28679bee92432a159042af9bc3c8606e5fc73af13c269f268b33ed43bbd168865ea10a9fd033303a0a5983fc5c7629e6a63d94b74be6a9a7d70552c817b572353a6d9000555e0963c34d8c5d4d8a0c634aec852d49e87097379cce27d9f3c9f28a01ec4ddac02f9bfbeaf0571e6cc911c59861c2f9e57a8ba34ae9251ce7f8a616278beec3c61603cdcca7636f51307a091e2194293f1110684e5e95a75fd6b3e5eb044693d518bc2af5be1022d8c88f5bc80e8ad95b930c4ffbe131648bea200e134b5279ab2f25f11fdf0e866b9729ae4add181a2a91229bd1fb77c37a0db4d0e6a523140b145637530e2abdfb1f0f507d1f1c7bcb98b676785761503bbfa33a3001e0971401e022d4f58302a22c7353dac5a439bc360afb9ebe47518e6a41228f7386ad172e94152ade06810368f42ee27aa1a40e582b2fbebd39a93fdd5f4ce5384b1e140da3b89e780447f77303771a29e5be98ef1ca2651f7bbb9bcfded848bce21c7920b5e110d2261c8512375841cea8f2995ad0f377e5fefba5a7c4e122205f14050bffdcece6b2af7807c1c24510a3ffeb7f41afcbd0f828978798537ebdcc966c0226446057d7743a79e58078f6fbb78160595f155736298c33c40a7b868732ed1b961acbbfaad327b6c8b1f43da2dc6417bb4bbd1883b267b431d698d83136031e97da47367ef6e13ecbda470c6409fbe10d83d191b2b6be3924238ee636ced01ee6b12bb458ac4933f3a7322d83a85759fa2b2a1bfb4dd7577964ac713db58217352dc516d22a742f8ebe18c1c1f15c9569016aa85e79a0e4698f78addc4ffb1e3f687a650acc27f83033fc57bd93fd15d430db3d7c9d907b5f2ecd4622e8041f84373a6ea89d676126b889267ec6cca18b79ea177ec712e8c7cf647c28c6f1182f387b60ef85b5d839087b9e297f6aa8c3c6ac997e38b863f74a8c5b170939301f5ebe347ce8cd57cd2ba6cce473c21b6a71c320c4ceefacfa0440f9ace24b11152ec80f8ba025dc483b6aec22fed90d3d3dbf1887d0b6b5d22a5c287055fc07244b4ca05487ad17c3ffed3981b81c71748baac228bfac7af1080842fdb42e1395ac2fe992f332774996e1d29ba9677cc5d786171961960cc69703e66a55cc08eb5ccd7fe1b2b67d168cf8503db7555c43b700eb95c65c65c90ec73021f326254991641d6dad346297fd78b4d2f82d2708ccd7d01e235b4bd71bc29eca269e10b377af356928f032259fd7c1aaaea15646e7a08e9b9be897f6b2c37d065c6625f0cc2298fd5c862272b36dd7eeb5cdb3187e127efb8d63a74b589110082fb90edffd759aaf17ebd11c516bf2f1c628db4e542c062adf617eb2aaa457e51fef1b4645b69c1d8fce09c52e0f33e764e6f2d5ce59ab5722661a22c5da5bc616f303c79c3ffe87ca72237e5997a56fef750635db7d13aa782189d252e2c326285c26964081fd0ca1f2514501f682f96f887686fe786d31edd9ee47ee07d64fb0c01aef4dccdaadb4ef02b4e79f02a1d224f11df7861b2c24b29af19ed4985078ec17b3f75407c2e06a6d4a9e40476fceec843c48b8e4aedbbaa161b088455dac9a0936e9b87683bbe26dc7a2cb6c5869c749c4de66310a6d764ea4ef46bd606619085711e25b57ad398a58297b50afea0fe0ab1472f34a26b93f974340f18266a80c96a103e2909545cd57dc78f1239cde93f76fb47630d67629bb62afa7fa5c6c181304c22d08cd31efe18935598387a8f42cd7992fa8c4fe98a162d5cf1a47e120e9a6d3a6455e11c658e4c7790f011a166074e3d18237f72c2f01d9eab231ad18eff01f55a1729fa6504fbdea48c6c5367dbd2234c6b1ed53edfd6d82905e950053f78c18372cb256782303f789d9e639bc47e1cad13529d86a4760a723cc9c26e6ebc398291d9b2b4aa7f0e1093dd2c92188056fb6e6022ae797b943e7081101bdd1cf8f575686825bd4c5a55a77cd1a7eb642156733f14831921f662d89d3252935a98ada18843d20afcc9eaac0c86f82e5235f0980180521f0b985fb6fed0a9593970f61527321cfb5eb9ba709316d98df236df641db89a39b3b6d1c5b9102305b0c6ba969bab39b017621ceb792e9e2b2d25dc554375ae68fbf07f021b01945c353fad83c6ff42d4192e8805a09bc21f1ce207ae7db4f434fbbfa662a9f08a442f78eb1160751abc7e5a5544678fcb1ff25d923518149f1258a5fa7b2b321fb393d8b32e77fe4ba8980538df5d60ae98d4ac49b6387717134d60cd29d6325f645a92e8c6d1c1288f6438697720c28165c9147a3571ae396fea65a0b6d5c256b80f14e5bfc7e9a14965490f8421bac53c6b81314f1606c10f49d630377ad21d75cc1aa4f77c56fe38ff385ff991a19c2907523c0907eec74a4fd950931f51c778804dc0d37581ddf62b2923bba393d50ded45c51a863968c15ea793f4f412953471760cae8745187c85387e0658554746bfc2b8988d00ec283cca6a6a248263eba6478fed99f89e0d07acfa1cfd31582a2b69540f9f953f1962bba5e50d81bab024ce41c1d695ba71a4e469ba8a9836ef4e3c92ec783c0b3204b00ffdf73188d7cf06dbd59f9e33f72b5e157f48a20f438202b008f84799093217e1d354b1c4f3244f81f59449e8bd18575df861640e3261f87ce629846fdcd3b89d1896d07ede0bb52d0ea25571cbc2b5332f820f7c41f70c0518fe6b71c302c270773ca0d3810095f52acebcb7bb1e805637d4019e5e5bb488e90424ca58ef64619774f2fd9bdafcaf4a42af9962dc87784f23abd5965ca6c2c81c7a32ac9acd7ecafb81dab9ca27fd229b554a16a5958ebfa9cc2fb122c6781a9cf5c2b5373a98199960e323d89bc1efcb577194d08e2d87a7de07cd07a383fa5b4cc6467759e58ad561cd93c8cdb8e3199651b0058c4b329ac211b6bec6c888b2e1911bfa9fa77267b2dd687a6767568010f0e30440446fff4fed6421e618af524c1add606c23d78560b7ed2bc0d9b84090a2fd8726d8ab4fb9548b3d5e68cd3a12dd111f1756427d806d290df0f20642ad665cbad6470162aad12dc3bba7de8bdd36b40acf40ae0bf2d9f3c72821bc627c9f83307be3b24d74a83a480151a4893025c53722d461c2717bd0d182ba0d07425f87cb1cb9c8b18d84283d30cc0271ee5f55061b4e189c32d100d9b3ef6d3bb10d7f251afa3ec5ca4f9964d5c7dc98e69fe6eb404e9fc071f26be9472e3ce9e3e54406e71a76330430c3fe2ccb94458535222b9efd76d992149c74f4dfbce89ab12c95b0223c2116110d42543f0e2ffeca29ebe58b1d76f0ec322612f608574a1ac7d2d8377b9feb16fb77941bbaa1551dd28c01994095301ede6eaf33461d0b2dc609af5859949b6d2ab90dd9b85f86845292aa4ac335b0678de40b123d2e9c18d60bef27721d86c4f0788423082c758b89f6e58dc41ac2199fdd936ce21c3433c27369bd773677f27e67240bd02a916f9b3c875db6d5f2cf72bf47fae1298dfe2a6837037ef6ae764dadb14be8b7eb72c2033c69875a3011b899abf8037fa4a4e07569cf1fb366f310c514ea2a1bb4622ea8de3d630aa0af3bdb1bad354cd9dba77aae02b6da930e2bf965443787861024dd08a94ad6d16e31711056fd4c0523b6faf25c678fde5f75fe94c2a44abe5e79a454e0ac28e205b30d6f6818d38ea5517dc4a0f781bd7ba3c7da70b282a0ab4e27e1ea654c711584ec8902fe1978022ebefcf4b754d4b882ff875febbfcd208b4d866b8ee9303e44252a258141f43b317793285a677db9798a4e009c9d661cfc931a9a365af25db79195f8da28f29f9a1f56f6fec3b4e08d5bf48508934213c3250fffd33b211198a127aebdfcecb19adf1b756c339577dd0da75386f82a3f42ae1698b6be31b5b6fd66b651eda6c83267e2aee6f1cdcccd85447dfd6b10e224e08d05c4495071f22dd4d0d31ce99a807002c6383db46aee0e3b6df06cd31300bb0ffde8aac03d1f35f5763840e6ce3644c8746c8673b682d623db09b1436863a98c95bc9e028c4444bdb54e0208405d39a27c6a5729576476677265b7c68722ea427c7000f2db7160bf889e33d4f59aa0e0bbd55a9e806c0cdcd429c9785d7eb29ee494b7505d882d8493b24e0cb77af9425b0bb121cafa9175b20f791c5d02820ba5c6fac1c46725457d27c80f9cf5027e30b638eb58e904e46c8d5782e859ad61ef550540c0c1b73afd9267ea33bc6d74c2f4a3a54540f592fe495fdbda06f6860a7f93e0c656c36766bbd2cd1b8178c0d3edf5f860cf0fc66fd3cca3f20c359a65d7fe62267d06a4e4c4aead49db45c6b1e13e55b713d27d3e4729dd82466e45d22c3e018720338700378133da093249358e1b335d37e77812631db6dedff73448ecfdf1b8637f4f837870a158d5e90b82626603abf7733ba675c14674d35d4f1be807b1cccc4dcd267cb1a4db2540f0afdee3160dbaaf7a3015acdf90c14b47055ab091bb1d3c1790f53b313dbdbaed50e183e284092663c71113a1f5f06d6c78599f22f6eb7b43837b77c957414ba803dc4fc79e1e3e3597d2e528e03e264b00bbf7105335881f0b3debcab2f896894ab65209a4e2369fcf3a3cec45c771b58d33e872dc8e04a5488f8ccc8ad1e90439966e1a85148c4f213646274435a34c13db81d19e6afaf63cb9ca40ec7c9fd88078c0fa41aa45c817df40ca88fd07a2248f1d101c2abbc9182b0f2cbdf57f24511868a283947076b8b0ad1e09a58421522bb9b0d9cd37264391517736c7e3911508e67ce0fc9bb371718c06cf8526c2f0037d317c7d8260a91e065591722e7241d1a588b9470eac96815eec7ae7152ecae902626a867a8ef7e9d82a14e0fe8b5aa951238cb5ba7f060183806c598ec1f29056306d6159348ed917b4151febfe2a197a80e1822e916dac60e70676befb93dae9b298e8cd00746689e3fdd815194095bb46bc650337ae8a0c68a7c297726532c86019528e7ff377ec472eb31e944a2bd16e394f26ed6d4cf570d54b562172f413c15c43be8cdf97060a47601f7e527fb9835b1e4528ffad6fc29cdd7e7623b22322cfab0c1a7a16327f104f580c1f85f1238f3786922d0e67476f17396e4e34757182f48c24bc05dcb0132b29233d01da09dcb547a553a6f32b975c978aefb21b91c384a4c055e707534df72f180e72bf789a6ad49a716495cc9c18ead95940146"

    
    let singers = await hre.ethers.getSigners();
    let signer = singers[0];

    const tx1 = await signer.sendTransaction({
        to: verifier,
        data: data
    });
    // console.log(tx1);
    const receipt1 = await tx1.wait();
    // console.log(receipt1);
    console.log(receipt1.gasUsed);


    // const Aggregator = await hre.ethers.getContractFactory("Aggregator");
    // const aggregator = Aggregator.attach(
    //     utils.getContractAddress("Aggregator")
    // );
    
    // const proof = utils.readProofCallData("data/agg.json")
    // const ids = [0, 1];
    // const tx2 = await aggregator.submit_batch(proof, ids);
    // const receipt2 = await tx2.wait()
    // console.log(receipt2.transactionHash);
    // console.log(receipt2.gasUsed);




}


main()
    .then(() => process.exit(0))
    .catch(e => {
        console.error(e);
        process.exit(1);
    })