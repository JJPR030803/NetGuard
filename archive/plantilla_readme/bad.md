x = func(y)
````
````

---

## Status Indicators

### For Incomplete Projects
````markdown
## Status: 🚧 Work in Progress

### Implemented ✅
- Feature A (fully functional)
- Feature B (core functionality complete)

### In Development 🚧
- Feature C (parser stage complete, AST pending)
- Feature D (planned architecture documented)

### Planned 📋
- Feature E
- Feature F
````

### For Complete Projects
````markdown
## Status: ✅ Production Ready

Last updated: [Date]
Maintained: Yes
````

---

## Tone and Language Guidelines

### Professional Voice
````markdown
✅ DO: "This system processes real-time sensor data..."
❌ DON'T: "So basically this thing kinda reads sensors and stuff..."

✅ DO: "Implemented using FastAPI for performance benefits"
❌ DON'T: "I chose FastAPI because it's really fast and cool"

✅ DO: "Currently refactoring authentication module"
❌ DON'T: "Auth is broken lol, need to fix"
````

### Technical Clarity
````markdown
✅ DO: Clear technical terms with context
"Uses Redis for caching frequently accessed queries, reducing database load by 60%"

❌ DON'T: Unexplained jargon
"Leverages Redis for performant data persistence layer optimization"
````

### Confidence Without Arrogance
````markdown
✅ DO: "Designed a custom protocol for efficient data transmission"
❌ DON'T: "Built the best protocol ever for data transmission"

✅ DO: "Reduced processing time from 500ms to 50ms through algorithm optimization"
❌ DON'T: "Made it super fast, way better than before"
````

---

## Special Case: Unfinished Projects

### Template for Honest Incompleteness
````markdown
# Project Name

> ⚠️ **Development Status:** Early stage - [X] complete

## What Works Now

[List functional components with detail]

## What's Missing

**Known Limitations:**
- Feature X (planned implementation: [approach])
- Optimization Y (needs: [specific work])

**Why Share This Anyway:**

This project demonstrates:
1. [Specific technical skill]
2. [Architecture/design capability]
3. [Problem-solving approach]

## Learning & Growth

**What I'd Do Differently:**
- [Technical lesson learned]
- [Process improvement identified]

**Next Steps:**
- [ ] Immediate: [task]
- [ ] Short-term: [task]
- [ ] Long-term: [vision]
````

---

## Academic Projects → Portfolio Transition

### Converting School Projects
````markdown
## Context & Evolution

**Original Assignment:** [Brief description]

**My Extensions:**
- ➕ Added [feature] beyond requirements
- ➕ Implemented [technology] not taught in course  
- ➕ Solved [real-world problem] version

**Academic → Professional:**
| Requirement | My Implementation | Why |
|-------------|-------------------|-----|
| Basic CRUD | RESTful API + Auth | Industry standard |
| CSV storage | PostgreSQL | Scalability |
| Console UI | Web interface | Usability |

**Grade Received:** [If notable]
**Skills Demonstrated:** [Professional relevance]
````

---

## Visual Assets Checklist

### Required for Portfolio Projects

- [ ] **Project logo or icon** (optional but professional)
- [ ] **Architecture diagram** (system overview)
- [ ] **Screenshot/GIF** of main interface or output
- [ ] **Code snippet** showing interesting implementation

### Creating Assets

**Screenshots:**
````bash
# Linux
gnome-screenshot -a  # Area selection

# macOS  
cmd + shift + 4
````

**GIFs:**
````bash
# Terminal recordings
asciinema rec demo.cast
asciinema upload demo.cast

# Screen recordings
peek  # Linux
LICEcap  # Cross-platform
````

**Hosting:**
- Commit to repo: `docs/images/` or `.github/assets/`
- Or use: imgur, GitHub issues (for URLs)

---

## README Anti-Patterns to Avoid

### ❌ DON'T
````markdown
# Bad Example 1: Obvious statements
"This is a project I made for learning Python"

# Bad Example 2: Apologetic tone
"Sorry this code is messy, I didn't have time to clean it"

# Bad Example 3: Over-promising
"Will revolutionize the industry" (for incomplete project)

# Bad Example 4: No installation steps
"Just run it" (without dependencies listed)

# Bad Example 5: Wall of text
[Three paragraphs without breaks or structure]

# Bad Example 6: Excessive emojis
"🔥🔥🔥 Super cool project 🚀🚀🚀 Check it out!!! 💯💯💯"

# Bad Example 7: TODO as content
"TODO: Write description"
````

### ✅ DO
````markdown
# Good Example: Clear, confident, structured

# Temperature Control System

> IoT system for intelligent thermal management using ML prediction

## Overview

This system combines ESP32 hardware with a FastAPI backend to provide
real-time temperature control. Uses machine learning to predict thermal
patterns and optimize energy usage.

**Key Features:**
- Real-time sensor monitoring (sub-second latency)
- ML-based temperature prediction (±0.5°C accuracy)
- Genetic algorithm optimization for control parameters

[Continues with structure from template...]
````

---

## SEO and Discoverability

### GitHub-Specific Optimization

**Topics:** Add relevant tags to repository
````
python, iot, machine-learning, fastapi, esp32, embedded-systems
````

**Description:** Use the one-liner under repo name
````
"IoT temperature control with ML prediction and heuristic optimization"
````

**Keywords in README:** Naturally include searchable terms
- Technology names (FastAPI, TensorFlow, React)
- Problem domains (IoT, network security, compiler design)
- Methodologies (machine learning, real-time systems)

---

## Quality Checklist

Before finalizing README, verify:

### Content
- [ ] Project purpose clear in first 3 lines
- [ ] Architecture explained with diagram
- [ ] Installation steps tested and accurate
- [ ] Code examples run without errors
- [ ] Technical depth appropriate for audience
- [ ] Status (complete/WIP) clearly indicated

### Formatting
- [ ] Headers follow hierarchy (no skipped levels)
- [ ] Code blocks have language specified
- [ ] Links work (relative paths correct)
- [ ] Images load properly
- [ ] No spelling/grammar errors
- [ ] Consistent formatting throughout

### Professionalism
- [ ] Confident but honest tone
- [ ] No apologetic language
- [ ] Technical terms explained or contextual
- [ ] No placeholder text ("TODO", "Lorem ipsum")
- [ ] Contact/contribution info appropriate

### Portfolio-Ready
- [ ] Demonstrates specific technical skills
- [ ] Shows problem-solving capability
- [ ] Includes visual elements
- [ ] Differentiated from academic assignment
- [ ] Suitable for recruiter/hiring manager review

---

## AI Agent Specific Instructions

When refactoring or creating README based on existing project:

1. **Analyze First:**
   - Read all source code to understand architecture
   - Identify key technologies and patterns
   - Note what's complete vs. incomplete
   - Find interesting technical decisions

2. **Extract Context:**
   - Project type (web app, CLI tool, library, etc.)
   - Primary language and frameworks
   - Intended use case
   - Current state of completion

3. **Generate Content:**
   - Start with template structure
   - Fill sections based on actual code
   - Create accurate code examples from project
   - Be honest about status
   - Highlight genuinely interesting aspects

4. **Create Diagrams:**
   - Use ASCII art for simple flows
   - Suggest mermaid syntax for complex architecture
   - Describe what diagram should show if can't generate

5. **Code Examples:**
   - Pull real code snippets from project
   - Ensure they're runnable and make sense standalone
   - Add comments for clarity
   - Show actual functionality, not pseudocode

6. **Tone Calibration:**
   - Professional but not stuffy
   - Confident but not arrogant
   - Honest about limitations
   - Focus on what works, not what's missing

7. **Validation:**
   - Check all code blocks for syntax
   - Verify links are properly formatted
   - Ensure header hierarchy is correct
   - Confirm markdown renders properly

---

## Example Prompts for AI Agents

### Complete Project
````
Create a professional portfolio README for this [project type] project.
Analyze the codebase and:
1. Generate an architecture diagram showing component interaction
2. Extract 2-3 code examples demonstrating key functionality
3. Write in confident professional tone suitable for hiring managers
4. Include installation steps and usage examples
5. Highlight technical decisions that show engineering maturity
6. Follow the structure in the AI_README_GUIDE.md
````

### Incomplete Project
````
Create an honest, professional README for this work-in-progress project.
Analyze the codebase and:
1. Clearly indicate what's implemented vs. planned
2. Explain what the completed components demonstrate (skills/knowledge)
3. Show working code examples for functional parts
4. Include a roadmap of planned features
5. Maintain professional tone while being transparent about status
6. Follow the structure in the AI_README_GUIDE.md
````

### School Project Refactor
````
Refactor this academic project README for professional portfolio.
Transform from school assignment to portfolio piece by:
1. Removing course-specific references
2. Highlighting extensions beyond requirements
3. Emphasizing practical applications
4. Showing technical depth and decisions
5. Comparing: assignment requirements vs. my implementation
6. Follow the structure in the AI_README_GUIDE.md
````

---

## Version History

- **v1.0** - Initial guide creation
- Add date stamps when updating this guide

---

## Quick Reference

**Mandatory Sections:** Title, Overview, Features, Tech Stack, Quick Start
**Optional Sections:** Roadmap, Contributing, License, Acknowledgments
**Always Include:** At least one diagram and one code example
**Tone:** Professional, confident, honest
**Length:** 500-2000 words ideal (adjust based on project complexity)

---

**This guide should be placed in:** `docs/AI_README_GUIDE.md` or `.github/AI_README_GUIDE.md`

**Usage:** Reference this file when instructing AI agents to generate/refactor project documentation.
