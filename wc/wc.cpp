// wc.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"

enum HashType
{
	MD2 = CALG_MD2,
	MD5 = CALG_MD5,
	SHA = CALG_SHA
};

#define SCAN_KEY_MD5_BUSIZE 255
char scan_key_md5[SCAN_KEY_MD5_BUSIZE];

unsigned char* hash_func(BYTE* input, int size, HashType type)
{
	HCRYPTPROV hCryptProv;
	HCRYPTHASH hHash;
	BYTE* pData;
	DWORD dwHashLength;
	DWORD dwLength;
	DWORD dwHashType = (DWORD)type;

	if (CryptAcquireContext(&hCryptProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT))
	{
		if (CryptCreateHash(hCryptProv, dwHashType, 0, 0, &hHash))
		{
			if (CryptHashData(hHash, input, size, 0))
			{
				CryptGetHashParam(hHash, HP_HASHSIZE, (BYTE*)&dwHashLength, &dwLength, 0);
				pData = new BYTE[dwHashLength];
				CryptGetHashParam(hHash, HP_HASHVAL, pData, &dwHashLength, 0);
				CryptDestroyHash(hHash);
				CryptReleaseContext(hCryptProv, 0);

				return pData;
			}
		}
	}

	return NULL;
}

void error_msg(LPTSTR lpszFunction)
{
	LPVOID lpMsgBuf;
	LPVOID lpDisplayBuf;
	DWORD dw = GetLastError();

	FormatMessage(
		FORMAT_MESSAGE_ALLOCATE_BUFFER |
		FORMAT_MESSAGE_FROM_SYSTEM |
		FORMAT_MESSAGE_IGNORE_INSERTS,
		NULL,
		dw,
		MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
		(LPTSTR)&lpMsgBuf,
		0, NULL);

	lpDisplayBuf = (LPVOID)LocalAlloc(LMEM_ZEROINIT,
		(lstrlen((LPCTSTR)lpMsgBuf) + lstrlen((LPCTSTR)lpszFunction) + 40) * sizeof(TCHAR));
	StringCchPrintf((LPTSTR)lpDisplayBuf,
		LocalSize(lpDisplayBuf) / sizeof(TCHAR),
		TEXT("%s failed with error %d: %s"),
		lpszFunction, dw, lpMsgBuf);

	MessageBox(NULL, (LPCTSTR)lpDisplayBuf, TEXT("Error"), MB_OK);

	LocalFree(lpMsgBuf);
	LocalFree(lpDisplayBuf);
}

int sql_execute_nonselect_stmt(sqlite3* db, char* sql)
{
	if (db == NULL || sql == NULL)
		return !SQLITE_OK;

	char* errmsg = NULL;
	int sql_ret_val = sqlite3_exec(db, sql, NULL, NULL, &errmsg);

	if (sql_ret_val != SQLITE_OK)
		printf("SQL Error: %s\n", errmsg);

	sqlite3_free(errmsg);

	return sql_ret_val;
}

int sql_ddl_init(sqlite3* db)
{
	if (db == NULL)
		return !SQLITE_OK;

	char* sql = "CREATE TABLE SCAN_FILE_DATA("  \
		"SCAN_KEY TEXT NOT NULL," \
		"FILE_KEY_MD5 TEXT NOT NULL," \
		"FILE_PATH TEXT NOT NULL," \
		"FILE_NAME TEXT NOT NULL," \
		"FILE_SIZE INT NOT NULL );";

	return sql_execute_nonselect_stmt(db, sql);
}

int sql_insert_file_data(sqlite3* db, TCHAR* filepath, TCHAR* filename, int filesize)
{
	if (db == NULL)
		return !SQLITE_OK;

	char sql[2048];
	memset(sql, 0, 2048);

	char filename_utf8[MAX_PATH];
	memset(filename_utf8, 0, MAX_PATH);

	int buffsize = lstrlen(filepath)*sizeof(char) + 1;
	char* filepath_utf8 = (char*)malloc(buffsize);
	memset(filepath_utf8, 0, buffsize);

	WideCharToMultiByte(CP_UTF8, 0, filename, -1, filename_utf8, MAX_PATH, NULL, NULL);
	WideCharToMultiByte(CP_UTF8, 0, filepath, -1, filepath_utf8, buffsize, NULL, NULL);

	#define MAX_INT_DIGITS 10

	char* hash_key = (char*)malloc(strlen(filename_utf8) + strlen(filepath_utf8) + MAX_INT_DIGITS + 4);
	memset(hash_key, 0, strlen(filename_utf8) + strlen(filepath_utf8) + MAX_INT_DIGITS + 4);
	sprintf(hash_key, "%s|%s|%ld", filepath_utf8, filename_utf8, filesize);

	unsigned char* md5_hash = hash_func((BYTE*)hash_key, strlen(hash_key), MD5);

	char md5_hash_hex[255];
	memset(md5_hash_hex, 0, 255);
	sprintf(md5_hash_hex, "%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x", md5_hash[0], md5_hash[1], md5_hash[2], md5_hash[3], md5_hash[4], md5_hash[5], 
		md5_hash[6], md5_hash[7], md5_hash[8], md5_hash[9], md5_hash[10], md5_hash[11], md5_hash[12], md5_hash[13], md5_hash[14], md5_hash[15]);

	sprintf(sql, "INSERT INTO SCAN_FILE_DATA (SCAN_KEY, FILE_KEY_MD5, FILE_PATH, FILE_NAME, FILE_SIZE) VALUES ('%s', '%s', '%s', '%s', %ld);", 
		scan_key_md5, md5_hash_hex, filepath_utf8, filename_utf8, filesize);

	free(filepath_utf8);
	free(md5_hash);

	return sql_execute_nonselect_stmt(db, sql);
}

void walk_the_tree(sqlite3* db, TCHAR* path)
{
	WIN32_FIND_DATA lpFindFileData;
	FINDEX_INFO_LEVELS fInfoLevelId = FindExInfoStandard;
	FINDEX_SEARCH_OPS fSearchOp = FindExSearchNameMatch;
	DWORD dwAdditionalFlags = FIND_FIRST_EX_LARGE_FETCH;
	HANDLE hFind;

	TCHAR* pattern = (TCHAR*)malloc((lstrlen(path) + MAX_PATH) * sizeof(TCHAR));
	memset(pattern, 0, (lstrlen(path) + MAX_PATH) * sizeof(TCHAR));
	lstrcat(pattern, TEXT("\\\\?\\"));
	lstrcat(pattern, path);
	lstrcat(pattern, TEXT("\\*.*"));
	
	hFind = FindFirstFileEx(pattern, fInfoLevelId, &lpFindFileData, fSearchOp, NULL, dwAdditionalFlags);

	if (hFind == INVALID_HANDLE_VALUE)
	{
		error_msg(TEXT("_tmain"));

		free(pattern);
		return;
	}

	do
	{
		if (lpFindFileData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
		{
			if (lstrcmp(lpFindFileData.cFileName, TEXT(".")) && lstrcmp(lpFindFileData.cFileName, TEXT("..")))
			{
				TCHAR* subpath = (TCHAR*)malloc((lstrlen(path) + MAX_PATH) * sizeof(TCHAR));
				memset(subpath, 0, (lstrlen(path) + MAX_PATH) * sizeof(TCHAR));

				lstrcat(subpath, path);
				lstrcat(subpath, TEXT("\\"));
				lstrcat(subpath, lpFindFileData.cFileName);

				// push test
				//_tprintf(TEXT("path: %s folder: %s\n"), subpath, lpFindFileData.cFileName);

				walk_the_tree(db, subpath);

				free(subpath);
			}
		} else 
		{
			TCHAR* filepath = (TCHAR*)malloc((lstrlen(path) + MAX_PATH) * sizeof(TCHAR));
			memset(filepath, 0, (lstrlen(path) + MAX_PATH) * sizeof(TCHAR));

			lstrcat(filepath, path);
			lstrcat(filepath, TEXT("\\"));
			lstrcat(filepath, lpFindFileData.cFileName);

			LARGE_INTEGER filesize;
			filesize.LowPart = lpFindFileData.nFileSizeLow;
			filesize.HighPart = lpFindFileData.nFileSizeHigh;

			_tprintf(TEXT("path: %s file: %s, size %ld B\n"), filepath, lpFindFileData.cFileName, filesize.QuadPart);
			sql_insert_file_data(db, path, lpFindFileData.cFileName, (int)filesize.QuadPart);

			free(filepath);
		}

	} while (FindNextFile(hFind, &lpFindFileData) != 0);

	free(pattern);

	DWORD dwError = GetLastError();
	if (dwError != ERROR_NO_MORE_FILES)
	{
		error_msg(TEXT("FindNextFile"));
	}

	FindClose(hFind);
}

void create_scan_key()
{
	memset(scan_key_md5, 0, SCAN_KEY_MD5_BUSIZE);

	char hash_key[SCAN_KEY_MD5_BUSIZE];
	memset(hash_key, 0, SCAN_KEY_MD5_BUSIZE);
	
	sprintf(hash_key, "%ld%d", time(0), GetTickCount());

	unsigned char* md5_hash = hash_func((BYTE*)hash_key, strlen(hash_key), MD5);

	sprintf(scan_key_md5, "%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x", md5_hash[0], md5_hash[1], md5_hash[2], md5_hash[3], md5_hash[4], md5_hash[5],
		md5_hash[6], md5_hash[7], md5_hash[8], md5_hash[9], md5_hash[10], md5_hash[11], md5_hash[12], md5_hash[13], md5_hash[14], md5_hash[15]);

	free(md5_hash);
}

int _tmain(int argc, _TCHAR* argv[])
{
	sqlite3* db;
	TCHAR* zErrMsg = NULL;
	int rc;

	rc = sqlite3_open("C:\\SQLite.db", &db);
	if (rc)
	{
		fprintf(stderr, "Can't open database: %s\n", sqlite3_errmsg(db));
		sqlite3_close(db);
		return(1);
	}

	create_scan_key();

	TCHAR* lpFilenName = TEXT("C:\\GuiXT");

	sql_ddl_init(db);

	PVOID OldValue = NULL;
	if (!Wow64DisableWow64FsRedirection(&OldValue))
		error_msg(TEXT("Wow64DisableWow64FsRedirection"));

	walk_the_tree(db, lpFilenName);
		
	if (!Wow64RevertWow64FsRedirection(OldValue))
		error_msg(TEXT("Wow64RevertWow64FsRedirection"));

	sqlite3_close(db);

	getchar();

	return 0;
}

