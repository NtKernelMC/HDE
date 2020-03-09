# Introduction 
HDE - Hooks Detection Engine<br/>
Task: Prevent WIN API & NT API hooks<br/>
Copyright: NtKernelMC<br/>
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
Build x86 or x64 static library for your future project.

# Contribute
Anyone can make this project better, do pull request with your designs!
