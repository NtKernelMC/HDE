# Introduction 
HDE - Hooks Detection Engine
Task: Prevent WIN API & NT API hooks
Copyright: NtKernelMC
Date: 29.05.2019

# FEATURES [EN]
	> Detection of inline hooks for many types (jmp, jmp ptr, call, call ptr)
	> Detection of export table hooks with protection to bypassing
	> Detection of import table hooks with protection to bypassing
	> Detection of vectored exception hooks for two types (PAGE_GUARD/PAGE_NOACCES)
	> Smart analysation system for all hooks types to prevent false-positives
	> Additional methods for controlling white-listed hooks list
	> Support for x86-x64 architectures and OS of Windows family from Vista+
# ФУНКЦИОНАЛ [RU]
	> Обнаружeние инлайн хуков различных видов (jmp, jmp ptr, call, call ptr)
	> Обнаружение хуков таблицы экспорта с защитой против обхода
	> Обнаружение хуков таблицы импорта с защитой против обхода
	> Обнаружение хуков работающих через векторный обработчик исключений двух видов (PAGE_GUARD/PAGE_NOACCES)
	> Умная система анализа для всех видов хуков для предотвращения ложных срабатываний
	> Дополнительный функционал для контроля вайт-листом разрешенных хуков
	> Поддержка для х86-х64 архитектур и операционных систем семейства Windows начиная с Vista и выше

# Build and Test
TODO: Describe and show how to build your code and run the tests. 

# Contribute
TODO: Explain how other users and developers can contribute to make your code better. 

If you want to learn more about creating good readme files then refer the following [guidelines](https://docs.microsoft.com/en-us/azure/devops/repos/git/create-a-readme?view=azure-devops). You can also seek inspiration from the below readme files:
- [ASP.NET Core](https://github.com/aspnet/Home)
- [Visual Studio Code](https://github.com/Microsoft/vscode)
- [Chakra Core](https://github.com/Microsoft/ChakraCore)