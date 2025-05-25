#include <Windows.h>
#include <thread>
#include <vector>
#include "Utilidades.h"

struct RegiaoCommit
{
	void* Endereco;
	SIZE_T Tamanho;
};

DWORD64 ObterTamanhoDoModulo(DWORD64 Module)
{
	PIMAGE_DOS_HEADER pDosHeader = PIMAGE_DOS_HEADER(Module);

	if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE)
	{
		Module += 4096;

		MEMORY_BASIC_INFORMATION mbi{ };

		if (VirtualQuery(PVOID(Module), &mbi, sizeof mbi))
			return mbi.RegionSize;

		return 0;
	}

	PIMAGE_NT_HEADERS pNTHeader = PIMAGE_NT_HEADERS(Module + pDosHeader->e_lfanew);

	if (pNTHeader->Signature != IMAGE_NT_SIGNATURE)
		return 0;

	if (pNTHeader->FileHeader.SizeOfOptionalHeader <= 0)
		return 0;

	return pNTHeader->OptionalHeader.SizeOfImage;
}

bool EsconderThread(HANDLE hThread)
{
	typedef NTSTATUS(NTAPI* pNtSetInformationThread)
		(HANDLE, UINT, PVOID, ULONG);
	NTSTATUS Status;

	pNtSetInformationThread NtSIT = (pNtSetInformationThread)
		GetProcAddress(GetModuleHandle(("ntdll.dll")),
			("NtSetInformationThread"));

	if (NtSIT == NULL)
		return false;

	if (hThread == NULL)
		Status = NtSIT(GetCurrentThread(),
			0x11,
			0, 0);
	else
		Status = NtSIT(hThread, 0x11, 0, 0);

	if (Status != 0x00000000)
		return false;
	else
		return true;
}

bool MemSeguro(uint8_t* destino, DWORD64 enderecoBase, size_t tamanho)
{
	size_t offset = 0;

	while (offset < tamanho)
	{
		MEMORY_BASIC_INFORMATION mbi;
		void* addr = (void*)(enderecoBase + offset);

		if (VirtualQuery(addr, &mbi, sizeof(mbi)) == 0)
			return false;

		size_t sizeToCopy = min(mbi.RegionSize, tamanho - offset);

		if ((mbi.State == MEM_COMMIT) &&
			(mbi.Protect & (PAGE_READONLY | PAGE_READWRITE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE)))
		{
			// Memoria legivel.
			memcpy(destino + offset, addr, sizeToCopy);
		}
		else
		{
			// Vamos ignorar p�ginas n�o leg�veis.
			memset(destino + offset, 0, sizeToCopy);
		}

		offset += sizeToCopy;
	}

	return true;
}

std::vector<RegiaoCommit> ObterRegioesCommitadasDoModulo()
{
	std::vector<RegiaoCommit> regioes;

	MEMORY_BASIC_INFORMATION mbi = {};

	BYTE* base = (BYTE*)GetModuleHandle(NULL);
	SIZE_T tamanho = ObterTamanhoDoModulo((DWORD64)base);

	BYTE* end = base + tamanho;
	BYTE* addr = base;

	while (addr < end && VirtualQuery(addr, &mbi, sizeof(mbi)) == sizeof(mbi))
	{
		if ((mbi.State == MEM_COMMIT) &&
			(mbi.Protect & (PAGE_READONLY | PAGE_EXECUTE_READ))) // Obter apenas as regi�es onde o certo � ser apenas leitura.
		{
			regioes.push_back({ mbi.BaseAddress, mbi.RegionSize });
		}

		addr += mbi.RegionSize;
	}

	return regioes;
}

void CheckRegiao(DWORD64 Regiao, DWORD64 Tamanho)
{
	// J� que nosso foco � a seguran�a, iremos esconder este thread.
	EsconderThread(GetCurrentThread());

	uint8_t* BufferOriginal = new uint8_t[Tamanho];
	uint8_t* BufferAtual = new uint8_t[Tamanho];

	if (!MemSeguro(BufferOriginal, Regiao, Tamanho))
		return;

	while (true)
	{
		if (!MemSeguro(BufferAtual, Regiao, Tamanho))
			return;

		// Comparar com o buffer original para verificar se houve modifica��es.
		if (memcmp(BufferOriginal, BufferAtual, Tamanho) != 0)
		{
			MessageBox(0, "Integridade comprometida.", "", MB_ICONINFORMATION | MB_TOPMOST); // Aqui voc� pode banir o usu�rio, encerrar o software, e etc ...
			exit(1);
		}

		std::this_thread::sleep_for(std::chrono::milliseconds(2000));
	}
}

DWORD WINAPI ACThread(LPVOID lp)
{
	// J� que nosso foco � a seguran�a, iremos esconder este thread.
	EsconderThread(GetCurrentThread());

	// E iremos criar threads, cada thread ser� respons�vel por verificar uma determinada regi�o em COMMIT. (Escolhi dividi as regi�es em cada thread para aumentar a efiencia da an�lise)
	auto regioes = ObterRegioesCommitadasDoModulo();

	for (const auto& reg : regioes)
	{
		DWORD64 ADDR_REG = (DWORD64)reg.Endereco;
		DWORD64 ADDR_SIZ = (DWORD64)reg.Tamanho;

		std::thread(CheckRegiao, ADDR_REG, ADDR_SIZ).detach();
	}

	return 0;
}

BOOL WINAPI DllMain(HMODULE hModule, DWORD ul_reason, LPVOID)
{
	if (ul_reason == DLL_PROCESS_ATTACH)
	{
		// Evitar chamadas repetidas.
		DisableThreadLibraryCalls(hModule);

		// J� que nosso foco � a seguran�a, iremos esconder este modulo removendo ela da lista.
		EsconderModulo(hModule);

		// Acionar a mensagem para verificar se o nosso modulo foi iniciado com sucesso.
		MessageBox(0, "Modulo de defesa iniciado!", "Obs", MB_ICONINFORMATION | MB_TOPMOST);

		// Vamos iniciar nosso thread.
		CreateThread(nullptr, 0, ACThread, nullptr, 0, nullptr);
	}

	return TRUE;
}