# Análise de Integridade da Memória

Com base na minha experiência na área de engenharia reversa, percebi que muitas funções críticas, como autenticação e segurança, podem ser facilmente contornadas com instruções simples como JMP, RET ou NOP. 
Por isso, decidi desenvolver este projeto, que monitora regiões específicas da memória para detectar alterações usando as funções memcmp e memcpy.

Observação: Este projeto pode conter falhas, pois foi desenvolvido com o propósito principal de adquirir experiência prática.

## Demonstração
![Demonstração do projeto](https://i.imgur.com/rZlcu9k.gif)

## Como usar

Basta carregar a dll no momento em que seu software for executado.
Lembre-se de carregar a dll com a arquitetura semelhante ao seu processo.