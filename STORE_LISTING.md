# Store Listing — MethodenAnalyser

## Deutsch

### Kurzbeschreibung (max 100 Zeichen)
Statischer Python-Code-Analyser — findet ungenutzte Imports, tote Definitionen und Code-Duplikate.

### Beschreibung (max 10.000 Zeichen)
MethodenAnalyser ist ein statischer Code-Analyser speziell fuer Python-Projekte. Er nutzt den Abstract Syntax Tree (AST) fuer praezise Analyse und bietet eine einfache Tkinter-GUI — keine Kommandozeile noetig, keine externen Abhaengigkeiten.

**Was MethodenAnalyser kann:**

- AST-basierte Analyse: Praezise statische Analyse ueber den Python Abstract Syntax Tree — keine Regex-Heuristiken
- Import-Tracking: Erkennt genutzte und ungenutzte Imports zuverlaessig
- Methoden-Katalog: Listet alle Funktionen, Methoden und Klassen mit Nutzungsstatus auf
- Duplikat-Erkennung: Findet aehnliche Code-Bloecke mit konfigurierbarem Schwellwert (Standard: 80%)
- Framework-Erkennung: Erkennt ob Definitionen von Tkinter, requests, asyncio und anderen Frameworks implizit genutzt werden
- Callback-Erkennung: Identifiziert Callback-Funktionen korrekt als genutzt (haeufige Fehlerquelle anderer Tools)
- Multi-File-Analyse: Ganze Python-Projekte rekursiv analysieren mit aggregiertem Report

**Was unterscheidet MethodenAnalyser von pylint, flake8 oder vulture?**

- Code-Aehnlichkeitserkennung: Kein anderes gaengiges Tool findet aehnliche (nicht identische) Code-Bloecke
- Framework-Awareness: Erkennt implizite Nutzung durch GUI-Frameworks und Bibliotheken
- GUI statt Terminal: Sofort nutzbar ohne Konfiguration oder Plugin-Installation
- Zero Dependencies: Laeuft mit reinem Python — kein pip install noetig

**Fuer wen ist MethodenAnalyser?**

Python-Entwickler, die ihren Code aufraeumen und toten Code finden moechten. Besonders nuetzlich bei gewachsenen Projekten, Code-Reviews und vor Refaktorierungen.

### Schluesselwoerter
Python, Code-Analyse, AST, statische Analyse, ungenutzte Imports, tote Methoden, Duplikat-Erkennung, Code-Qualitaet, Refactoring, Entwickler-Tool

### Kategorie
Developer Tools

---

## English

### Short Description (max 100 chars)
Static Python code analyzer — finds unused imports, dead definitions and code duplicates.

### Description (max 10,000 chars)
MethodenAnalyser is a static code analyzer built specifically for Python projects. It uses the Abstract Syntax Tree (AST) for precise analysis and provides a simple Tkinter GUI — no command line needed, no external dependencies.

**What MethodenAnalyser does:**

- AST-based Analysis: Precise static analysis via the Python Abstract Syntax Tree — no regex heuristics
- Import Tracking: Reliably detects used and unused imports
- Method Catalog: Lists all functions, methods and classes with their usage status
- Duplicate Detection: Finds similar code blocks with a configurable threshold (default: 80%)
- Framework Awareness: Detects whether definitions are implicitly used by Tkinter, requests, asyncio and other frameworks
- Callback Detection: Correctly identifies callback functions as used (a common false positive in other tools)
- Multi-File Analysis: Recursively analyze entire Python projects with an aggregated report

**What sets MethodenAnalyser apart from pylint, flake8 or vulture?**

- Code similarity detection: No other common tool finds similar (not identical) code blocks
- Framework awareness: Recognizes implicit usage by GUI frameworks and libraries
- GUI instead of terminal: Immediately usable without configuration or plugin installation
- Zero dependencies: Runs with pure Python — no pip install required

**Who is MethodenAnalyser for?**

Python developers who want to clean up their code and find dead code. Especially useful for legacy projects, code reviews and before refactoring.

### Keywords
Python, code analysis, AST, static analysis, unused imports, dead methods, duplicate detection, code quality, refactoring, developer tool

### Category
Developer Tools
