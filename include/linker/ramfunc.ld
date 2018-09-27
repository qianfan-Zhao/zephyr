	SECTION_DATA_PROLOGUE(.ramfunc,,)
	{
		. = ALIGN( 1 << LOG2CEIL(__ramfunc_ram_end - __ramfunc_ram_start));
		__ramfunc_ram_start = .;
		KERNEL_INPUT_SECTION(.ramfunc)
		KERNEL_INPUT_SECTION(".ramfunc.*")
		. = ALIGN(32);
		. = ALIGN( 1 << LOG2CEIL(__ramfunc_ram_end - __ramfunc_ram_start));
		__ramfunc_ram_end = .;
	} GROUP_DATA_LINK_IN(RAMABLE_REGION, ROMABLE_REGION)

	__ramfunc_rom_start = LOADADDR(.ramfunc);