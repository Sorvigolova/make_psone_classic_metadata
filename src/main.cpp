
#include "main.h"

long iso_header_size = 0x100000;
u8 entry_hash[0x14];

void sha1(unsigned char *input, size_t ilen, unsigned char output[20])
{
	SHA_CTX sha;
	SHAInit(&sha);
	SHAUpdate(&sha, input, ilen);
	SHAFinal(output, &sha);
	memset(&sha, 0, sizeof(SHA_CTX));
}

int decrypt_iso_map(unsigned char *iso_map_buf)
{
	//printf("Decrypting ISO map\n");
	//Start Kirk.
	kirk_init();
	unsigned char pgd_key[0x10];
	memset(pgd_key, 0, 0x10);

	unsigned char *map_enc = new unsigned char[0x2A0];
	memcpy (map_enc, iso_map_buf, 0x2A0);

	int pgd_size = decrypt_pgd(map_enc, 0x2A0, 2, pgd_key);
	if (pgd_size > 0)
	{
		//printf("ISO map successfully decrypted\n");
	}
	else
	{
		printf("Error! ISO map decryption failed\n");
		return -1;
	}

	//Copying and cleaning decrypted data.
	memcpy(iso_map_buf, map_enc + 0x90, pgd_size );
	memset(iso_map_buf + pgd_size, 0, (0x2A0 - pgd_size));
	delete[] map_enc;
	return 0;
}

int decrypt_iso_header(unsigned char *iso_header_buf)
{
	//printf("Decrypting ISO header\n");
	//Start Kirk.
	kirk_init();
	unsigned char pgd_key[0x10];
	memset(pgd_key, 0, 0x10);

	unsigned char *header_enc = new unsigned char[0xB6600];
	memcpy (header_enc, iso_header_buf + 0x400, 0xB6600);

	int pgd_size = decrypt_pgd(header_enc, 0xB6600, 2, pgd_key);
	if (pgd_size > 0)
	{
		//printf("ISO header successfully decrypted\n");
	}
	else
	{
		printf("Error! ISO header decryption failed\n");
		return -1;
	}

	//Copying and cleaning decrypted data.
	memcpy(iso_header_buf + 0x400, header_enc + 0x90, pgd_size );
	memset(iso_header_buf + (pgd_size + 0x400), 0, (0x100000 - (pgd_size + 0x400)));
	delete[] header_enc;
	return 0;
}

int add_metadata_offset(FILE *dat, int disc_number)
{
	long cd_entries_offset = 0x200;
	long cd_entry = 0x0400 + iso_header_size * (disc_number - 1);

	_fseeki64(dat, (cd_entries_offset + (disc_number - 1) * 4), SEEK_SET);
	fwrite (&cd_entry, sizeof(cd_entry), 1, dat);
	return 0;
}

int add_metadata(FILE *pbp, FILE *dat, long psar_offset, unsigned long disc_offset)
{
	//Reading iso header to memory.
	unsigned char *iso_header_buf = new unsigned char[iso_header_size];
	unsigned long iso_header_offset = unsigned long(psar_offset + disc_offset);
	_fseeki64(pbp, iso_header_offset, SEEK_SET);
	fread(iso_header_buf, 1, iso_header_size, pbp);

	//Checking for encrypted part and decrypting it.
	unsigned char enc_magic[0x4];
	bool isEncrypted = false;
	memset(enc_magic, 0, 0x4);
	memcpy(enc_magic, iso_header_buf + 0x400 , sizeof (enc_magic));
	if (memcmp(enc_magic, pgd_magic, sizeof (enc_magic)) == 0)
	{
		decrypt_iso_header(iso_header_buf);
		isEncrypted = true;
	}

	//fixing iso offset inside iso header.
	(*(unsigned long*)&iso_header_buf[0xBFC]) = unsigned long(disc_offset + 0x100000);

	//fixing hash table inside iso header.
	int table_offset = 0x4000;
	unsigned long block_count = 0;
	unsigned long block_offset, hash_offset, block_flag_offset;
	unsigned short block_size;
	unsigned long iso_offset = (unsigned long)(iso_header_offset + (unsigned long)iso_header_size);
	bool isLatest_block = false;
	unsigned short block_flag = 1;

	_fseeki64(pbp, (unsigned long)iso_offset, SEEK_SET);

	while (isLatest_block == false)
	{
		block_offset = (*(unsigned long*)&iso_header_buf[(unsigned long)((block_count * 0x20) + (unsigned long)table_offset)]);
		block_size = (*(unsigned short*)&iso_header_buf[(unsigned long)((block_count * 0x20) + (unsigned long)table_offset + 0x4)]);
		//printf("block offset is  0x%X\n", block_offset);
		//printf("block size is  0x%X\n", block_size);
		if (block_size == 0)
			isLatest_block = true;

		if (isLatest_block == false)
		{
			u8 *entry_buf = new u8[block_size];
			//printf("block offset is  0x%X\n", (unsigned long)(iso_offset + (unsigned long)block_offset));
			_fseeki64(pbp, (unsigned long)(iso_offset + (unsigned long)block_offset), SEEK_SET);
			fread(entry_buf, block_size, 1, pbp);

			memset(entry_hash,0 , 0x10);
			sha1(entry_buf, block_size, entry_hash );
			delete[] entry_buf;
			hash_offset = (unsigned long)((unsigned long)table_offset + (unsigned long)block_count * 0x20 + 0x08);
			memcpy(iso_header_buf + hash_offset, entry_hash, 0x10);
			block_flag_offset = (unsigned long)((unsigned long)table_offset + (unsigned long)block_count * 0x20 + 0x06);
			if (isEncrypted == false)
				memcpy(iso_header_buf + block_flag_offset, &block_flag, 0x2);

			block_count++;
		}
	}

	fwrite (iso_header_buf, iso_header_size, 1, dat);
	return 0;
}

int handle_multi_disc(FILE *pbp, long psar_offset)
{
	FILE *dat = NULL;
	dat = fopen("ISO.BIN.DAT", "wb");
	fwrite (multi_iso_magic, 0x10, 1, dat);

	//Checking for encrypted iso map and decrypting it.
	unsigned char map_magic[0x4];
	memset(map_magic, 0, 0x4);
	unsigned char *iso_map_buf = new unsigned char[0x2A0];
	_fseeki64(pbp, (psar_offset + 0x200), SEEK_SET);
	fread(iso_map_buf, 1, 0x2A0, pbp);
	memcpy(map_magic, iso_map_buf + 0 , sizeof (map_magic));
	if (memcmp(map_magic, pgd_magic, sizeof (map_magic)) == 0)
		decrypt_iso_map(iso_map_buf);

	//Reading offsets for all discs.
	unsigned long disc1_offset, disc2_offset, disc3_offset, disc4_offset, disc5_offset;
	disc1_offset = (*(unsigned long*)&iso_map_buf[0x00]);
	disc2_offset = (*(unsigned long*)&iso_map_buf[0x04]);
	disc3_offset = (*(unsigned long*)&iso_map_buf[0x08]);
	disc4_offset = (*(unsigned long*)&iso_map_buf[0x0C]);
	disc5_offset = (*(unsigned long*)&iso_map_buf[0x10]);

	if (disc1_offset)
	{
		printf("Disc 1 offset: 0x%X\n", disc1_offset);
		add_metadata_offset(dat, 1);
		_fseeki64(dat, 0x400 , SEEK_SET);
		add_metadata(pbp, dat, psar_offset, disc1_offset);
	}
	if (disc2_offset)
	{
		printf("Disc 2 offset: 0x%X\n", disc2_offset);
		add_metadata_offset(dat, 2);
		_fseeki64(dat, (iso_header_size + 0x400), SEEK_SET);
		add_metadata(pbp, dat, psar_offset, disc2_offset);
	}
	if (disc3_offset)
	{
		printf("Disc 3 offset: 0x%X\n", disc3_offset);
		add_metadata_offset(dat, 3);
		_fseeki64(dat, (iso_header_size * 2 + 0x400), SEEK_SET);
		add_metadata(pbp, dat, psar_offset, disc3_offset);
	}
	if (disc4_offset)
	{
		printf("Disc 4 offset: 0x%X\n", disc4_offset);
		add_metadata_offset(dat, 4);
		_fseeki64(dat, (iso_header_size * 3 + 0x400), SEEK_SET);
		add_metadata(pbp, dat, psar_offset, disc4_offset);
	}
	if (disc5_offset)
	{
		printf("Disc 5 offset: 0x%X\n", disc5_offset);
		add_metadata_offset(dat, 5);
		_fseeki64(dat, (iso_header_size * 4 + 0x400), SEEK_SET);
		add_metadata(pbp, dat, psar_offset, disc5_offset);
	}
	printf("\n");

	//writing title id.
	unsigned char title_id[0x10];
	memset(title_id, 0, 0x10);
	memcpy(title_id, iso_map_buf + 0x60, 0x10);
	_fseeki64(dat, 0x260, SEEK_SET);
	fwrite (title_id, 0x10 , 1, dat);
	fclose(dat);
	return 0;
}

int handle_single_disc(FILE *pbp, long psar_offset)
{
	FILE *dat = NULL;
	dat = fopen("ISO.BIN.DAT", "wb");

	_fseeki64(dat, 0x0 , SEEK_SET);
	add_metadata(pbp, dat, psar_offset, 0);
	fclose(dat);
	return 0;
}

int main (int argc, char *argv[])
{
	FILE *pbp = NULL;
	char file_magic[0x4];
	
	if (argc < 2)
	{
		printf("Usage: make_psone_classic_matadata.exe <file EBOOT.PBP>\n");
		return 0;
	}

	printf("Loading EBOOT.PBP...\n");
	//printf("Opening EBOOT.PBP\n");
	pbp = fopen(argv[1], "rb");
	if (pbp == NULL)
	{
		printf("Error! Could not open EBOOT.PBP file.\n");
		return 0;
	}

	//Checking pbp file magic.
	fread(file_magic, 0x4, 1, pbp);
	_fseeki64(pbp, 0, SEEK_SET);
	if (memcmp(pbp_magic, file_magic, 4))
	{
		printf("Error! Invalid EBOOT.PBP file detected.\n");
		return 0;
	}

	//printf("Reading header\n");
	char pbp_header[0x28];
	fread(pbp_header, sizeof(pbp_header), 1, pbp);
	_fseeki64(pbp, 0, SEEK_SET);

	long psar_offset;
	psar_offset = (*(long*)&pbp_header[0x24]);
	printf("DATA.PSAR offset: 0x%x\n\n", psar_offset);

	printf("Creating metadata file...\n");

	//Checking for multidisc.
	unsigned char psar_magic[0x10];
	memset(psar_magic, 0, 0x10);
	bool isMultidisc;

	_fseeki64(pbp, psar_offset, SEEK_SET);
	fread(psar_magic, 0x10, 1, pbp);
	if (memcmp(psar_magic, iso_magic, 0xC) != 0)
	{
		if (memcmp(psar_magic, multi_iso_magic, 0x10) != 0)
		{
			printf("Error! Unknown image detected.\n");
			return 0;
		}
		else
		{
			printf("Multidisc image detected.\n");
			isMultidisc = true;
		}
	}
	else
	{
		printf("Single-disc image detected.\n\n");
		isMultidisc = false;
	}
	if (isMultidisc)
		handle_multi_disc(pbp, psar_offset);
	else
		handle_single_disc(pbp, psar_offset);

	fclose(pbp);

	//Adding ECDSA sign.
	printf("Signing metadata file...\n");
	kirk_init();
	FILE *data = NULL;
	data = fopen("ISO.BIN.DAT", "rb");
	if (data == NULL)
	{
		printf("Error! Could not open ISO.BIN.DAT file.\n");
		return 0;
	}
	//printf("Data loaded.\n");
	_fseeki64(data, 0, SEEK_END);
	unsigned long data_size = ftell(data);
	_fseeki64(data, 0, SEEK_SET);
	//printf("Size of ISO.BIN.DAT: 0x%X bytes\n", data_size);
	if (data_size >= 0x80000000)
	{
		printf("Error! Input file is too big.\n");
		return 0;
	}
	//printf("Computing SHA1 hash...\n");
	unsigned char hash[0x14];
	memset(hash, 0, 0x14);
	unsigned char *sha1_buf = new unsigned char[data_size];
	_fseeki64(data, 0, SEEK_SET);
	fread(sha1_buf, data_size, 1, data);
	sha1(sha1_buf, data_size, hash);
	delete[] sha1_buf;
	fclose(data);

	int k;
	printf("SHA1: ");
	for (k = 0; k < 0x14; k++)
	printf("%02X", hash[k]);
	printf("\n");

	unsigned char curve_p[] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x01, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
	unsigned char curve_a[] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x01, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFC};
	unsigned char curve_b[] = {0xA6, 0x8B, 0xED, 0xC3, 0x34, 0x18, 0x02, 0x9C, 0x1D, 0x3C, 0xE3, 0x3B, 0x9A, 0x32, 0x1F, 0xCC, 0xBB, 0x9E, 0x0F, 0x0B};
	unsigned char curve_n[] = {0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE, 0xFF, 0xFF, 0xB5, 0xAE, 0x3C, 0x52, 0x3E, 0x63, 0x94, 0x4F, 0x21, 0x27};
	unsigned char curve_gx[] = {0x12, 0x8E, 0xC4, 0x25, 0x64, 0x87, 0xFD, 0x8F, 0xDF, 0x64, 0xE2, 0x43, 0x7B, 0xC0, 0xA1, 0xF6, 0xD5, 0xAF, 0xDE, 0x2C};
	unsigned char curve_gy[] = {0x59, 0x58, 0x55, 0x7E, 0xB1, 0xDB, 0x00, 0x12, 0x60, 0x42, 0x55, 0x24, 0xDB, 0xC3, 0x79, 0xD5, 0xAC, 0x5F, 0x4A, 0xDF};
	unsigned char private_key[] = {0x00, 0xbf, 0x21, 0x22, 0x4b, 0x04, 0x1f, 0x29, 0x54, 0x9d, 0xb2, 0x5e, 0x9a, 0xad, 0xe1, 0x9e, 0x72, 0x0a, 0x1f, 0xe0, 0xf1};
	unsigned char public_key[] = {
	0x94, 0x8D, 0xA1, 0x3E, 0x8C, 0xAF, 0xD5, 0xBA, 0x0E, 0x90, 0xCE, 0x43, 0x44, 0x61, 0xBB, 0x32, 0x7F, 0xE7, 0xE0, 0x80,
	0x47, 0x5E, 0xAA, 0x0A, 0xD3, 0xAD, 0x4F, 0x5B, 0x62, 0x47, 0xA7, 0xFD, 0xA8, 0x6D, 0xF6, 0x97, 0x90, 0x19, 0x67, 0x73
	};
	unsigned char *signature_r = new unsigned char[0x15];
	unsigned char *signature_s = new unsigned char[0x15];

	ecdsa_set_curve(curve_p, curve_a, curve_b, curve_n, curve_gx, curve_gy);
	ecdsa_set_priv(private_key);

	//printf("Computing signature...\n");
	ecdsa_sign(hash, signature_r, signature_s);
	unsigned char *signature = new unsigned char[0x28];
	memcpy(signature, signature_r + 1, 0x14);
	memcpy(signature + 0x14, signature_s + 1, 0x14);
	int n;
	printf("Signature: ");
	for (n = 0; n < 0x28; n++)
	printf("%02X", signature[n]);
	printf("\n");

	//printf("Verifying signature...\n");
	ecdsa_set_pub(public_key);
	if (!ecdsa_verify(hash, signature_r, signature_s))
	{
		printf("Signature status: FAIL.\n");
		return 0;
	};
	printf("Signature status: OK.\n");

	FILE *f;
	f = fopen("ISO.BIN.DAT", "ab");
	fwrite(signature, 0x28, 1, f);
	fclose(f);
	delete[] signature;
	printf("Done.\n");

	return 0;
};