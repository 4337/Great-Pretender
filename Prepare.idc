#include <idc.idc>

/*
* Saneskobar broni się nadal !
* ********
* Skrypt mn. poprawia nazwy funkcji bibliotecznych 
* w wersji objętej embargiem (dla ubogich) -- dlatego embargo jest dobre bo uczymy się je omijać <br/>
* im większe embargo tym bardziej chcemy je ominąć, po co i dlaczego ? Nikt nie wie ( tu jest miejce dla tych wszystkich wierzących w symulacje ).
* To jest właśnie "psychological acceptability" w teroii bezpieczeństwa (cyber -- nie wiem jakie macie inne teorie) .
*
* --------
* Miało być również dla 32-bitów, ale mnie się nie chce.
* Testowane wyłącznie z nvcontainer.exe (x64)
* ********
* echovsky 04/10/2024
*/

extern DOS_HDR_STRUCT_ID;
extern NT_HDR_STRUCT_ID;
extern OPTIONAL_x64_HDR_STRUCT_ID;
extern SECTION_HDR_STRUCT_ID;
extern IMAGE_IMPORT_DESCRIPTOR_HDR_STRUCT_ID;

static order_16(x) {
      return  ((0xFF00 & x << 8) | (x >> 8));
}

static order_32(x) {
       return  ((x >> 24) & 0x000000FFul) | 
               ((x >>  8) & 0x0000FF00ul) | 
               ((x <<  8) & 0x00FF0000ul) | 
               ((x << 24) & 0xFF000000ul);
}


static find_module_base(file_name) {
     
	  auto base;
	  auto name;
	  
	  base = get_first_module();
	  if(base == -1) return -1;
	  do {
		  name = get_module_name(base);
		  if(strstr(name, file_name) != -1) {
		     return base;
		  }
      } while((base = get_next_module(base)) != -1);
      return -1;
	  
}

static pe32_struct() {
       return -1;
}

static pe64_struct() {
       
	   auto sid;
	   auto mid;
	   DOS_HDR_STRUCT_ID = AddStrucEx(-1,"ECHO_DOS_HDR",0);
	   sid = GetStrucIdByName("ECHO_DOS_HDR");
	   //    AddStrucMember(mId,"Signature",0,FF_BYTE,-1,4)
	   mid = AddStrucMember(sid,"e_magic",	0,	FF_BYTE,	-1,	2);  
	   mid = AddStrucMember(sid,"e_cblp",	2,	FF_BYTE,	-1,	2);
	   mid = AddStrucMember(sid,"e_cp",	4,	FF_BYTE,	-1,	2);
	   mid = AddStrucMember(sid,"e_crlc",	6,	FF_BYTE,	-1,	2);
	   mid = AddStrucMember(sid,"e_cparhdr",	8,	FF_BYTE,	-1,	2);
	   mid = AddStrucMember(sid,"e_minalloc",	0xA,	FF_BYTE,	-1,	2);
	   mid = AddStrucMember(sid,"e_maxalloc",	0xc,	FF_BYTE,	-1,	2);
	   mid = AddStrucMember(sid,"e_ss",	0xe,	FF_BYTE,	-1,	2);
	   mid = AddStrucMember(sid,"e_sp",	0x10,	FF_BYTE,	-1,	2);
	   mid = AddStrucMember(sid,"e_csum",	0x12,	FF_BYTE,	-1,	2);
	   mid = AddStrucMember(sid,"e_ip",	0x14,	FF_BYTE,	-1,	2);
	   mid = AddStrucMember(sid,"e_cs",	0x16,	FF_BYTE,	-1,	2);
	   mid = AddStrucMember(sid,"e_ifarlc",	0x18,	FF_BYTE,	-1,	2);
	   mid = AddStrucMember(sid,"e_ovno",	0x1a,	FF_BYTE,	-1,	2);
	   mid = AddStrucMember(sid,"e_res",	0x1c,	FF_BYTE,	-1,	2);
	   
	   mid = AddStrucMember(sid,"e_un1",	0x1e,	FF_BYTE,	-1,	2);
	   mid = AddStrucMember(sid,"e_un2",	0x20,	FF_BYTE,	-1,	2);
	   mid = AddStrucMember(sid,"e_un3",	0x22,	FF_BYTE,	-1,	2);
	   
	   mid = AddStrucMember(sid,"e_oemid",	0x24,	FF_BYTE,	-1,	2);
	   mid = AddStrucMember(sid,"e_oeminfo",	0x26,	FF_BYTE,	-1,	2);
	   mid = AddStrucMember(sid,"e_ores2",	0x28,	FF_BYTE,	-1,	2);
	   
	   mid = AddStrucMember(sid,"e_un3",	0x2a,	FF_BYTE,	-1,	2);
	   mid = AddStrucMember(sid,"e_un3",	0x2c,	FF_BYTE,	-1,	2);
	   mid = AddStrucMember(sid,"e_un3",	0x2e,	FF_BYTE,	-1,	2);
	   mid = AddStrucMember(sid,"e_un3",	0x30,	FF_BYTE,	-1,	2);
	   mid = AddStrucMember(sid,"e_un3",	0x32,	FF_BYTE,	-1,	2);
	   mid = AddStrucMember(sid,"e_un3",	0x34,	FF_BYTE,	-1,	2);
	   mid = AddStrucMember(sid,"e_un3",	0x36,	FF_BYTE,	-1,	2);
	   mid = AddStrucMember(sid,"e_un3",	0x38,	FF_BYTE,	-1,	2);
	   mid = AddStrucMember(sid,"e_un3",	0x3a,	FF_BYTE,	-1,	2);
	   
	   mid = AddStrucMember(sid,"e_lfanew",	0x3a,	FF_BYTE,	-1,	2);
	   
	   NT_HDR_STRUCT_ID = AddStrucEx(-1,"ECHO_NT_HDR",0);
	   sid = GetStrucIdByName("ECHO_NT_HDR");
	   mid = AddStrucMember(sid,"Signature",	0,	FF_BYTE,	-1,	4);
	   mid = AddStrucMember(sid,"Machine",	4,	FF_BYTE,	-1,	2);
	   mid = AddStrucMember(sid,"NumberOfSections",	6,	FF_BYTE,	-1,	2);
	   mid = AddStrucMember(sid,"TimeDateStamp",	8,	FF_BYTE,	-1,	4);
	   mid = AddStrucMember(sid,"PointerToSymbolTable",	12,	FF_BYTE,	-1,	4);
	   mid = AddStrucMember(sid,"NumberOfSymbols",	16,	FF_BYTE,	-1,	4);
	   mid = AddStrucMember(sid,"SizeOfOptionalHeader",	20,	FF_BYTE,	-1,	2);
	   mid = AddStrucMember(sid,"Characteristics",	22,	FF_BYTE,	-1,	2);
	   
	   OPTIONAL_x64_HDR_STRUCT_ID = AddStrucEx(-1,"ECHO_x64_OPTIONAL_HDR",0);
	   sid = GetStrucIdByName("ECHO_x64_OPTIONAL_HDR");
	   mid = AddStrucMember(sid,"Magic",	0,	FF_BYTE,	-1,	2);
	   mid = AddStrucMember(sid,"MajorLinkerVersion",	2,	FF_BYTE,	-1,	1);
	   mid = AddStrucMember(sid,"MinorLinkerVersion",	3,	FF_BYTE,	-1,	1);
	   mid = AddStrucMember(sid,"SizeOfCode",	4,	FF_BYTE,	-1,	4);
	   mid = AddStrucMember(sid,"SizeOfInitializedData",	8,	FF_BYTE,	-1,	4);
	   mid = AddStrucMember(sid,"SizeOfUninitializedData",	12,	FF_BYTE,	-1,	4);
	   mid = AddStrucMember(sid,"AdresOfEntryPoint",	16,	FF_BYTE,	-1,	4);
	   mid = AddStrucMember(sid,"BaseOfCode",	20,	FF_BYTE,	-1,	4);
	   mid = AddStrucMember(sid,"ImageBase",	24,	FF_BYTE,	-1,	8);
	   mid = AddStrucMember(sid,"SectionAlignment",	32,	FF_BYTE,	-1,	4);
	   mid = AddStrucMember(sid,"FileAlignment",	36,	FF_BYTE,	-1,	4);
	   mid = AddStrucMember(sid,"MajorOperatingSystemVersion",	40,	FF_BYTE,	-1,	2);
	   mid = AddStrucMember(sid,"MinorOperatingSystemVersion",	42,	FF_BYTE,	-1,	2);
	   mid = AddStrucMember(sid,"MajorImage",	44,	FF_BYTE,	-1,	2);
	   mid = AddStrucMember(sid,"MajorSubsytemVersion",	46,	FF_BYTE,	-1,	2);
	   mid = AddStrucMember(sid,"MinorSubsytemVersion",	48,	FF_BYTE,	-1,	2);
	   mid = AddStrucMember(sid,"Win32VersionValue",	50,	FF_BYTE,	-1,	4);
	   mid = AddStrucMember(sid,"SizeOfImage",	54,	FF_BYTE,	-1,	4);
	   mid = AddStrucMember(sid,"SizeOfHeaders",	58,	FF_BYTE,	-1,	4);
	   mid = AddStrucMember(sid,"CheckSum",	62,	FF_BYTE,	-1,	4);
	   mid = AddStrucMember(sid,"SubSystem",	66,	FF_BYTE,	-1,	2);
	   mid = AddStrucMember(sid,"DllCharacterics",	68,	FF_BYTE,	-1,	2);
	   mid = AddStrucMember(sid,"SizeOfStackReserve",	70,	FF_BYTE,	-1,	8);
	   mid = AddStrucMember(sid,"SizeOfStackCommit",	78,	FF_BYTE,	-1,	8);
	   mid = AddStrucMember(sid,"SizeOfHeapReserve",	86,	FF_BYTE,	-1,	8);
	   mid = AddStrucMember(sid,"SizeOfHeapCommit",	94,	FF_BYTE,	-1,	8);
	   mid = AddStrucMember(sid,"LoaderFlags",	104,	FF_BYTE,	-1,	4);
	   mid = AddStrucMember(sid,"NumberOfRvaAndSizez",	108,	FF_BYTE,	-1,	4);
	   
	   SECTION_HDR_STRUCT_ID = AddStrucEx(-1,"ECHO_SECTION_HDR",0);
	   sid = GetStrucIdByName("ECHO_SECTION_HDR");
	   mid = AddStrucMember(sid,"ExportDirectoryRVA",	0,	FF_BYTE,	-1,	4);
	   mid = AddStrucMember(sid,"ExportDirectorySize",	4,	FF_BYTE,	-1,	4);
	   mid = AddStrucMember(sid,"ImportDirectoryRVA",	8,	FF_BYTE,	-1,	4);
	   mid = AddStrucMember(sid,"ImportDirectorySize",	12,	FF_BYTE,	-1,	4);
	   mid = AddStrucMember(sid,"ResourceDirectoryRVA",	16,	FF_BYTE,	-1,	4);
	   mid = AddStrucMember(sid,"ResourceDirectorySize",	20,	FF_BYTE,	-1,	4);
	   mid = AddStrucMember(sid,"ExceptionDirectoryRVA",	24,	FF_BYTE,	-1,	4);
	   mid = AddStrucMember(sid,"ExceptionDirectorySize",	28,	FF_BYTE,	-1,	4);
	   mid = AddStrucMember(sid,"SecurityDirectoryRVA",	32,	FF_BYTE,	-1,	4);
	   mid = AddStrucMember(sid,"SecurityDirectorySize",	36,	FF_BYTE,	-1,	4);
	   mid = AddStrucMember(sid,"RelocationDirectoryRVA",	40,	FF_BYTE,	-1,	4);
	   mid = AddStrucMember(sid,"RelocationDirectorySize",	44,	FF_BYTE,	-1,	4);
	   mid = AddStrucMember(sid,"DebugDirectoryRVA",	48,	FF_BYTE,	-1,	4);
	   mid = AddStrucMember(sid,"DebugDirectorySize",	52,	FF_BYTE,	-1,	4);
	   mid = AddStrucMember(sid,"ArchitecutureDirectoryRVA",	56,	FF_BYTE,	-1,	4);
	   mid = AddStrucMember(sid,"ArchitectureDirectorySize",	60,	FF_BYTE,	-1,	4);
	   mid = AddStrucMember(sid,"Reserved1",	64,	FF_BYTE,	-1,	4);
	   mid = AddStrucMember(sid,"Reserved2",	68,	FF_BYTE,	-1,	4);
	   mid = AddStrucMember(sid,"TLSDirectoryRVA",	72,	FF_BYTE,	-1,	4);
	   mid = AddStrucMember(sid,"TLSDirectorySize",	76,	FF_BYTE,	-1,	4);
	   mid = AddStrucMember(sid,"ConfigurationDirectoryRVA",	80,	FF_BYTE,	-1,	4);
	   mid = AddStrucMember(sid,"ConfigurationDirectorySize",	84,	FF_BYTE,	-1,	4);
	   mid = AddStrucMember(sid,"BoundImportDirectoryRVA",	88,	FF_BYTE,	-1,	4);
	   mid = AddStrucMember(sid,"BoundImportDirectorySize",	92,	FF_BYTE,	-1,	4);
	   mid = AddStrucMember(sid,"ImportAddressTableDirectoryRVA",	96,	FF_BYTE,	-1,	4);
	   mid = AddStrucMember(sid,"ImportAddressTableDirectorySize",	100,	FF_BYTE,	-1,	4);
	   mid = AddStrucMember(sid,"DelayImportDirectoryRVA",	104,	FF_BYTE,	-1,	4);
	   mid = AddStrucMember(sid,"DelayImportDirectorySize",	108,	FF_BYTE,	-1,	4);
	   mid = AddStrucMember(sid,"NetMetadataDirectoryRVA",	112,	FF_BYTE,	-1,	4);
	   mid = AddStrucMember(sid,"NetMetadataDirectorySize",	116,	FF_BYTE,	-1,	4);
	  
	  IMAGE_IMPORT_DESCRIPTOR_HDR_STRUCT_ID = AddStrucEx(-1,"ECHO_IMAGE_DESCRIPTOR_HDR",0);
	  sid = GetStrucIdByName("ECHO_IMAGE_DESCRIPTOR_HDR");
	  mid = AddStrucMember(sid,"OriginalFirstThunk",	0,	FF_BYTE,	-1,	4);   /* characterics || originalThunk */
	  mid = AddStrucMember(sid,"TimeDateStamp",	4,	FF_BYTE,	-1,	4);
	  mid = AddStrucMember(sid,"ForwaderChain",	8,	FF_BYTE,	-1,	4);
	  mid = AddStrucMember(sid,"Name",	12,	FF_BYTE,	-1,	4);
	  mid = AddStrucMember(sid,"FirstThunk",	16,	FF_BYTE,	-1,	4);
	  //...
	   
}

static preparing(base) {

       auto nt;
	   
	   auto timestamp;
	   
	   auto linker_version_mj;
	   auto linker_version_mn;
	   
	   auto imports_directory;
	   
       MakeStructEx(base, -1, "ECHO_DOS_HDR");
	   
	   nt = dword(base + 0x3a);
	   nt = nt >> 16;            

	   msg("dos->e_lfanew: 0x%x, nt offset: 0x%x \n",nt, base + nt);
	   
	   MakeStructEx(base + nt, -1, "ECHO_NT_HDR");    //jest sztos
	   
	   nt = base + nt;
	   
	   timestamp = Dword(nt + 8);
	   
	   msg("compilation timestamp: %d, hex:0x%04x\n", timestamp, timestamp);
	   
	   MakeStructEx(nt + sizeof("ECHO_NT_HDR"), -1, "ECHO_x64_OPTIONAL_HDR"); 
	   
	   linker_version_mj = Byte(nt + sizeof("ECHO_NT_HDR") + 2);
	   linker_version_mn = Byte(nt + sizeof("ECHO_NT_HDR") + 3);
	   
	   msg("linker version: %d.%d, hex:0x%x.0x%x\n", linker_version_mj, linker_version_mn, linker_version_mj, linker_version_mn);
	   
	   MakeStructEx(nt + sizeof("ECHO_NT_HDR") + sizeof("ECHO_x64_OPTIONAL_HDR"), -1, "ECHO_SECTION_HDR");
	   
	   imports_directory = base + Dword(nt + sizeof("ECHO_NT_HDR") + sizeof("ECHO_x64_OPTIONAL_HDR") + 8);
	   
	   msg("imports directory: 0x%x, size: %d\n", imports_directory, Dword(nt + sizeof("ECHO_NT_HDR") + sizeof("ECHO_x64_OPTIONAL_HDR") + 12));
	   
	   msg("original first thunk: 0x%x\n", Dword(imports_directory));
	   
	   MakeStructEx(imports_directory, -1, "ECHO_IMAGE_DESCRIPTOR_HDR");
	   
	   auto i;
	   auto iat_dir_size;
	   
	   iat_dir_size = Dword(nt + sizeof("ECHO_NT_HDR") + sizeof("ECHO_x64_OPTIONAL_HDR") + 12) / sizeof("ECHO_IMAGE_DESCRIPTOR_HDR");
	   
	   auto of_thunk_addr;
	   auto f_thunk_addr;
	   auto func_name;
	   for(i=0; i<iat_dir_size - 1;i++) {    /* import directory entries [ECHO_IMAGE_DESCRIPTOR_HDR][N] */
	       
		   of_thunk_addr = base + Dword(imports_directory);
		   f_thunk_addr = base + Dword(imports_directory + 16);
		   
		   msg("Repairing %s IAT items\n",get_strlit_contents(base + Dword(imports_directory+12),-1, STRTYPE_C ));
		   
		   while((func_name = get_name(Qword(f_thunk_addr))) != 0) {
		    
			     //func_name = get_name(Qword(f_thunk_addr));
				 
                 msg("addr:0x%x point to %s (fixing format and name)\n",f_thunk_addr, func_name);
				 MakeQword(f_thunk_addr);
				 set_name(f_thunk_addr,"echo_"+func_name);
                 of_thunk_addr = of_thunk_addr + 8;
			     f_thunk_addr  = f_thunk_addr  + 8;
			
		   }
		   imports_directory = imports_directory + sizeof("ECHO_IMAGE_DESCRIPTOR_HDR");
	   }
      
}

static init() {

       pe64_struct();
	   pe32_struct();
}

static clean() {
 
       del_struc(DOS_HDR_STRUCT_ID);
	   del_struc(NT_HDR_STRUCT_ID);
	   del_struc(OPTIONAL_x64_HDR_STRUCT_ID);
	   del_struc(IMAGE_IMPORT_DESCRIPTOR_HDR_STRUCT_ID);

}

static main()
{
       auto base;
	   
	   init();
	   
       base = find_module_base("nvcontainer.exe");
	   msg("nvcontainer.exe base address: 0x%x\n", base);
	   
	   preparing(base);
	   
	   //clean();

}