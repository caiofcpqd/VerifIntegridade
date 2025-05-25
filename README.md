# Análise de integridade da memoria

Com minhas experiências na área da engenharia reversa, percebi que muitas funções (como de autenticação, segurança) são fácilmente ignoradas com apenas um JMP, RET, ou NOP.
Então decidi desenvolver um projeto que consiste em um monitoramente de algumas regiões específica da memória com o objetivo de detectar alterações usando memcmp e memcpy.

Obs: Este projeto pode conter falhas, pois foi desenvolvido apenas para adquirir experiências.

## Demonstração
[![Veja o vídeo](https://img.youtube.com/vi/bBv0Z0sMm6c/hqdefault.jpg)](https://www.youtube.com/watch?v=bBv0Z0sMm6c)

## Como usar

Basta carregar a dll no momento em que seu software for executado.
Lembre-se de carregar a dll com a arquitetura semelhante ao seu processo.