/*
 * Copyright (c) Daniel Phillips, 2002-2013
 * License for distribution granted under the terms of the GPL Version 3
 * The original author reserves the right to dual license this work
 * These lines must be preserved as is in any derivative of this work
 */

#include "tux3user.h"
#include "options.h"

static struct optv *optstart(void *work, int size)
{
	struct optv *optv = work;
	*optv = (struct optv){ .size = size };
	return optv;
}

static int is_number(const char *str)
{
	const unsigned char *num = (const unsigned char *)str;
	unsigned c;

	while ((c = *num++)) {
		if (c - '0' >= 10)
			return 0;
	}

	return 1;
}

static int optparse(struct options *options, struct optv *optv, const char **argv, int argc, int *pos)
{
	struct opt *top = (void *)optv + optv->size;
	const char *arg, *why;
	char *errout = (char *)optv->argv;
	int fake = !optv->size, terse = 0, longlen = 0, rule;
	int free = (char *)(top - optv->optc) - (char *)(optv->argv + optv->argc);
	int maxerr = fake ? 0 : (char *)top - errout;
	struct options *option;

	optv->err = 0;

	arg = argv[(*pos)++];
	if (options && *arg == '-' && *(arg + 1)) {
		const char *val = NULL;
		if (*++arg == '-') {
			if (!*++arg)
				return 1;
			longlen = (val = strchr(arg, '=')) ? val++ - arg : strlen(arg);
			terse = 0;
		} else
			terse = *arg++;

		do {
			for (option = options; option->name; option++)
				if (terse ? !!strchr(option->terse, terse) : !memcmp(option->name, arg, longlen))
					break;
			if (!option->name)
				goto name;
			if (terse && (option->rule & OPT_ANYARG) && *arg)
				val = arg;
			else if ((option->rule & OPT_ANYARG) == OPT_HASARG && !val) {
				why = "must have a value";
				if (*pos >= argc)
					goto fail;
				val = argv[(*pos)++];
			}
			optv->optc++;
			if (!(rule = option->rule) && val) {
				why = "must not have a value";
				goto fail;
			}
			if (!fake) {
				if ((free -= sizeof(struct opt)) < 0)
					goto full;
				if (!(rule & OPT_MANY)) {
					struct opt *seen = top;
					why = "given more than once";
					while (--seen > top - optv->optc)
						if (option - options == seen->index)
							goto fail;
				}
				if (rule & OPT_NUMBER) {
					if (!is_number(val)) {
						why = "must be numeric";
						goto fail;
					}
				}
				*(top - optv->optc) = (struct opt){option - options, val ? : option->defarg};
			}
		} while (terse && !(rule & ~OPT_MANY) && (terse = *arg++));

		return 0;
	}
	if (!fake) {
		if ((free -= sizeof(arg)) < 0)
			goto full;
		optv->argv[optv->argc] = arg;
	}
	optv->argc++;

	return 0;

name:
	if (terse)
		snprintf(errout, maxerr, "Unknown option -%c", terse);
	else
		snprintf(errout, maxerr, "Unknown option --%.*s", longlen, arg);
	return optv->err = -EINVAL;

fail:
	if (terse)
		snprintf(errout, maxerr, "Option -%c (%s) %s", terse, option->name, why);
	else
		snprintf(errout, maxerr, "Option --%s %s", option->name, why);
	return optv->err = -EINVAL;

full:
	snprintf((char *)optv->argv, maxerr, "Out of space in optv");
	return optv->err = -E2BIG;
}

int opthead(struct options *options, int *argc, const char ***argv, void *work, int size, int stop)
{
	struct optv *optv = optstart(work, size);
	int pos = 0;

	while (pos < *argc) {
		int err = optparse(options, optv, *argv, *argc, &pos);
		if (err) {
			if (err < 0)
				return err;
			options = NULL;
		}
		if (stop && optv->argc >= stop) {
			while (pos < *argc)
				optv->argv[optv->argc++] = (*argv)[pos++];
			break;
		}
	}
	if (optv->size) {
		*argc = optv->argc;
		*argv = optv->argv;
	}

	return optv->optc;
}

int optscan(struct options *options, int *argc, const char ***argv, void *work, int size)
{
	return opthead(options, argc, argv, work, size, 0);
}

int optspace(struct options *options, int argc, const char *argv[])
{
	struct optv fake = {};
	optscan(options, &argc, &argv, &fake, 0);
	int size = sizeof(fake) + fake.argc * sizeof(char *) + fake.optc * sizeof(struct opt);
	return fake.err ? 100 : size;
}

int optcount(void *work, int opt)
{
	int count = 0;
	for (int i = 0; i < ((struct optv *)work)->optc; i++)
		count += optindex(work, i) == opt;
	return count;
}

const char *opterror(void *work)
{
	struct optv *optv = work;
	return optv->err ? (const char *)optv->argv : NULL;
}

/* Generate help text */

struct emit {
	char *text;
	int full, size, over;
};

static int __printf(2, 3)
emit(struct emit *text, char *fmt, ...)
{
	va_list args;
	va_start(args, fmt);
	int room = text->full - text->size, over = 0;
	int size = vsnprintf(text->text + text->size, room, fmt, args);
	va_end(args);
	if (size > room) {
		text->over += over = size - room;
		size = room;
	}
	text->size += size;
	return over;
}

static int emitpad(struct emit *text, int pad)
{
	return emit(text, "%*s", pad, "");
}

static int emitend(struct emit *text)
{
	return emit(text, "\n");
}

static int emitrule(struct emit *text, struct options *option)
{
	if ((option->rule & 3)) {
		const char *type = option->arghelp ? : (option->rule & OPT_NUMBER) ? "number" : "value";
		int optional = (option->rule & 3) == OPT_OPTARG;
		if (optional)
			emit(text, "[=%s]", type);
		else
			emit(text, "=%s", type);
	}
	return 0;
}

int opthelp(void *buf, int bufsize, struct options *options, int tabs[3], char *lead, int brief)
{
	int tab0 = tabs ? tabs[0] : 3;
	int tab1 = tabs ? tabs[1] : 30;
	int tab2 = tabs ? tabs[2] : 80;
	struct emit *text = &(struct emit){
		.text	= buf,
		.full	= bufsize,
	};
	struct options *option;

	emit(text, "%s%s", lead, brief ? " " : lead[0] ? "\n" : "");

	int i, left = brief ? 0 : text->size;
	for (option = options; option->name; option++) {
		const char *terse = option->terse;
		if (brief) {
			for (i = 0; i < 2; i++) {
				int mark = text->size, over = text->over;
				emit(text, "[");
				while (*terse) {
					unsigned char c = *terse++;
					if (c > ' ') // !iscntrl
						emit(text, "-%c|", c);
				}
				emit(text, "--%s", option->name);
				emitrule(text, option);
				emit(text, "] ");
				if (text->size - left < tab2)
					break;
				text->size = mark;
				text->over = over;
				emitend(text);
				left = text->size;
				emitpad(text, tab0);
			}
			continue;
		}

		emitpad(text, tab0);
		emit(text, "--%s", option->name);
		emitrule(text, option);
		while (*terse) {
			unsigned char c = *terse++;
			if (c > ' ') // !iscntrl
				emit(text, ", -%c", c);
		}
		if (option->help) {
			int col = text->size + text->over - left, pad = tab1 > col ? tab1 - col : 0;
			emit(text, "%*s", pad, " ");
			const char *help = option->help;
			int tail = strlen(help);
			while (1) {
				char *top = text->text + text->full;
				col = text->size + text->over - left;
				int room = tab2 > col ? tab2 - col : 0;
				int size = tail < room ? tail : room;
				int free = top - (text->text + text->size);
				int mark = text->size, over = text->over;
				if (size > free) {
					text->over += size - free;
					size = free;
				}
				if (text->size == text->full)
					break;
				memcpy(text->text + text->size, help, size);
				text->size += size;
				if (tail <= size)
					break;
				text->size = mark;
				text->over = over;
				int wrap = size, most = tab2 - tab1 - 1;
				if (most > 10)
					most = 10;
				while (wrap > size - most)
					if (help[wrap--] == ' ') {
						size = wrap + 2;
						text->size--;
						break;
					}
				text->size += size;
				help += size;
				tail -= size;
				emitend(text);
				left = text->size + text->over;
				emitpad(text, tab1);
			}
		}
		emitend(text);
		left = text->size + text->over;
	}

	return -text->over;
}

const char *optbasename(const char *argv0)
{
	const char *p;

	if (!argv0 || !*argv0)
		return "";

	p = argv0 + strlen(argv0);

	while (argv0 < p) {
		if (*p == '/')
			return p + 1;
		p--;
	}

	return argv0;
}
