#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <dirent.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <pwd.h>
#include <signal.h>
#include <time.h>

#define MAX_TOKENS 128
#define TOKEN_DELIM " \t\r\n"
#define INITIAL_HISTORY_CAP 128
#define INITIAL_JOBS_CAP 32

typedef struct {
    char **entries;
    size_t size;
    size_t cap;
} History;

typedef enum { JOB_RUNNING, JOB_DONE } JobStatus;

typedef struct {
    int id;
    pid_t pid;
    char *cmd;
    JobStatus status;
} Job;

typedef struct {
    Job *arr;
    size_t size;
    size_t cap;
    int next_id;
} JobList;

History history;
JobList jobs;
volatile sig_atomic_t sigchld_flag = 0;

void history_init(void);
void history_add(const char *line);
void history_print(void);
void history_free(void);

void jobs_init(void);
int jobs_add(pid_t pid, const char *cmd);
Job* jobs_find_by_pid(pid_t pid);
Job* jobs_find_by_id(int id);
void jobs_remove_done(void);
void jobs_print(void);
void jobs_free(void);

void sigchld_handler(int signo);
void reap_children(void);

char *build_cmd_from_tokens(char **tokens, int ntokens);
int is_builtin(const char *cmd);
int run_builtin(char **args);

char **split_line(char *line, int *ntokens);
void free_tokens(char **tokens, int ntokens);

int copy_file(const char *src, const char *dst);

void launch_external(char **args, int ntokens, int bg);

void history_init() {
    history.cap = INITIAL_HISTORY_CAP;
    history.size = 0;
    history.entries = malloc(history.cap * sizeof(char *));
    if (!history.entries) {
        perror("malloc");
        exit(1);
    }
}

void history_add(const char *line) {
    if (history.size >= history.cap) {
        size_t newcap = history.cap * 2;
        char **tmp = realloc(history.entries, newcap * sizeof(char *));
        if (!tmp) {
            perror("realloc");
            return;
        }
        history.entries = tmp;
        history.cap = newcap;
    }
    history.entries[history.size++] = strdup(line ? line : "");
}

void history_print() {
    for (size_t i = 0; i < history.size; ++i) {
        printf("%4zu  %s\n", i + 1, history.entries[i]);
    }
}

void history_free() {
    for (size_t i = 0; i < history.size; ++i) free(history.entries[i]);
    free(history.entries);
}

void jobs_init() {
    jobs.cap = INITIAL_JOBS_CAP;
    jobs.size = 0;
    jobs.next_id = 1;
    jobs.arr = malloc(jobs.cap * sizeof(Job));
    if (!jobs.arr) {
        perror("malloc");
        exit(1);
    }
}

int jobs_add(pid_t pid, const char *cmd) {
    if (jobs.size >= jobs.cap) {
        size_t newcap = jobs.cap * 2;
        Job *tmp = realloc(jobs.arr, newcap * sizeof(Job));
        if (!tmp) {
            perror("realloc");
            return -1;
        }
        jobs.arr = tmp;
        jobs.cap = newcap;
    }
    int id = jobs.next_id++;
    jobs.arr[jobs.size].id = id;
    jobs.arr[jobs.size].pid = pid;
    jobs.arr[jobs.size].cmd = cmd ? strdup(cmd) : strdup("");
    if (!jobs.arr[jobs.size].cmd) {
        perror("strdup");
        jobs.arr[jobs.size].cmd = strdup("");
    }
    jobs.arr[jobs.size].status = JOB_RUNNING;
    jobs.size++;
    return id;
}

Job* jobs_find_by_pid(pid_t pid) {
    for (size_t i = 0; i < jobs.size; ++i) if (jobs.arr[i].pid == pid) return &jobs.arr[i];
    return NULL;
}

Job* jobs_find_by_id(int id) {
    for (size_t i = 0; i < jobs.size; ++i) if (jobs.arr[i].id == id) return &jobs.arr[i];
    return NULL;
}

void jobs_remove_done() {
    size_t j = 0;
    for (size_t i = 0; i < jobs.size; ++i) {
        if (jobs.arr[i].status == JOB_DONE) {
            free(jobs.arr[i].cmd);
            continue;
        }
        if (i != j) jobs.arr[j] = jobs.arr[i];
        j++;
    }
    jobs.size = j;
}

void jobs_print() {
    for (size_t i = 0; i < jobs.size; ++i) {
        printf("[%d] %s %s (pid %d)\n",
               jobs.arr[i].id,
               jobs.arr[i].status == JOB_RUNNING ? "Running" : "Done",
               jobs.arr[i].cmd ? jobs.arr[i].cmd : "",
               (int)jobs.arr[i].pid);
    }
}

void jobs_free() {
    for (size_t i = 0; i < jobs.size; ++i) free(jobs.arr[i].cmd);
    free(jobs.arr);
}

void sigchld_handler(int signo) {
    (void)signo;
    sigchld_flag = 1;
}

void reap_children() {
    int status;
    pid_t pid;
    while ((pid = waitpid(-1, &status, WNOHANG)) > 0) {
        Job *j = jobs_find_by_pid(pid);
        if (j) {
            j->status = JOB_DONE;
            if (WIFEXITED(status)) {
                printf("\n[%d]+  Done %s (exit %d)\n", j->id, j->cmd ? j->cmd : "", WEXITSTATUS(status));
            } else if (WIFSIGNALED(status)) {
                printf("\n[%d]+  Killed %s (signal %d)\n", j->id, j->cmd ? j->cmd : "", WTERMSIG(status));
            } else {
                printf("\n[%d]+  Done %s\n", j->id, j->cmd ? j->cmd : "");
            }
            fflush(stdout);
        }
    }
    jobs_remove_done();
    sigchld_flag = 0;
}

char *build_cmd_from_tokens(char **tokens, int ntokens) {
    if (!tokens || ntokens <= 0) return strdup("");
    size_t len = 0;
    for (int i = 0; i < ntokens; ++i) len += strlen(tokens[i]) + 1;
    char *s = malloc(len + 1);
    if (!s) return NULL;
    s[0] = '\0';
    for (int i = 0; i < ntokens; ++i) {
        strcat(s, tokens[i]);
        if (i != ntokens - 1) strcat(s, " ");
    }
    return s;
}

int is_builtin(const char *cmd) {
    const char *list[] = {"cd","pwd","ls","mkdir","rmdir","touch","rm","cp","mv","cat","echo","help","exit","history","clear","which","jobs","fg","bg", NULL};
    for (int i = 0; list[i]; ++i) if (strcmp(cmd, list[i]) == 0) return 1;
    return 0;
}

int builtin_cd(char **args) {
    if (!args[1]) {
        const char *home = getenv("HOME");
        if (!home) {
            struct passwd *pw = getpwuid(getuid());
            home = pw ? pw->pw_dir : "/";
        }
        if (chdir(home) != 0) perror("cd");
    } else {
        if (chdir(args[1]) != 0) perror("cd");
    }
    return 1;
}

int builtin_pwd(char **args) {
    char cwd[4096];
    (void)args;
    if (getcwd(cwd, sizeof(cwd))) printf("%s\n", cwd);
    else perror("pwd");
    return 1;
}

int builtin_ls(char **args) {
    char *path = args[1] ? args[1] : ".";
    DIR *d = opendir(path);
    if (!d) { perror("ls"); return 1; }
    struct dirent *entry;
    while ((entry = readdir(d)) != NULL) {
        if (entry->d_name[0] == '.') continue;
        printf("%s  ", entry->d_name);
    }
    printf("\n");
    closedir(d);
    return 1;
}

int builtin_mkdir(char **args) {
    if (!args[1]) { fprintf(stderr, "mkdir: missing operand\n"); return 1; }
    if (mkdir(args[1], 0755) != 0) perror("mkdir");
    return 1;
}

int builtin_rmdir(char **args) {
    if (!args[1]) { fprintf(stderr, "rmdir: missing operand\n"); return 1; }
    if (rmdir(args[1]) != 0) perror("rmdir");
    return 1;
}

int builtin_touch(char **args) {
    if (!args[1]) { fprintf(stderr, "touch: missing file operand\n"); return 1; }
    int fd = open(args[1], O_CREAT | O_WRONLY, 0644);
    if (fd < 0) perror("touch");
    else close(fd);
    return 1;
}

int builtin_rm(char **args) {
    if (!args[1]) { fprintf(stderr, "rm: missing operand\n"); return 1; }
    for (int i = 1; args[i]; ++i) {
        if (unlink(args[i]) != 0) perror("rm");
    }
    return 1;
}

int copy_file(const char *src, const char *dst) {
    int in = open(src, O_RDONLY);
    if (in < 0) return -1;
    int out = open(dst, O_CREAT | O_WRONLY | O_TRUNC, 0644);
    if (out < 0) { close(in); return -1; }
    char buf[8192];
    ssize_t r;
    while ((r = read(in, buf, sizeof(buf))) > 0) {
        ssize_t written = 0;
        while (written < r) {
            ssize_t w = write(out, buf + written, (size_t)r - written);
            if (w < 0) {
                close(in); close(out);
                return -1;
            }
            written += w;
        }
    }
    if (r < 0) { close(in); close(out); return -1; }
    if (close(in) < 0) perror("close");
    if (close(out) < 0) perror("close");
    return 0;
}

int builtin_cp(char **args) {
    if (!args[1] || !args[2]) { fprintf(stderr, "cp: missing operand\n"); return 1; }
    if (copy_file(args[1], args[2]) != 0) perror("cp");
    return 1;
}

int builtin_mv(char **args) {
    if (!args[1] || !args[2]) { fprintf(stderr, "mv: missing operand\n"); return 1; }
    if (rename(args[1], args[2]) != 0) {
        if (copy_file(args[1], args[2]) == 0) {
            if (unlink(args[1]) != 0) perror("mv");
        } else perror("mv");
    }
    return 1;
}

int builtin_cat(char **args) {
    if (!args[1]) { fprintf(stderr, "cat: missing file operand\n"); return 1; }
    for (int i = 1; args[i]; ++i) {
        int fd = open(args[i], O_RDONLY);
        if (fd < 0) { perror("cat"); continue; }
        char buf[8192];
        ssize_t r;
        while ((r = read(fd, buf, sizeof(buf))) > 0) {
            ssize_t w = write(STDOUT_FILENO, buf, (size_t)r);
            if (w < 0) break;
        }
        if (r < 0) perror("read");
        close(fd);
    }
    return 1;
}

int builtin_echo(char **args) {
    int i = 1;
    while (args[i]) {
        if (i > 1) putchar(' ');
        printf("%s", args[i]);
        i++;
    }
    putchar('\n');
    return 1;
}

int builtin_help(char **args) {
    (void)args;
    const char *msg =
        "SimpleShell built-in commands:\n"
        "cd pwd ls mkdir rmdir touch rm cp mv cat echo help exit history clear which jobs fg bg\n";
    printf("%s", msg);
    return 1;
}

int builtin_exit(char **args) {
    (void)args;
    history_free();
    jobs_free();
    exit(0);
    return 0;
}

int builtin_history(char **args) {
    (void)args;
    history_print();
    return 1;
}

int builtin_clear(char **args) {
    (void)args;
    printf("\033[H\033[J");
    return 1;
}

char *find_in_path(const char *cmd) {
    char *path = getenv("PATH");
    if (!path) return NULL;
    char *p = strdup(path);
    if (!p) return NULL;
    char *saveptr = NULL;
    char *dir = strtok_r(p, ":", &saveptr);
    while (dir) {
        size_t len = strlen(dir) + strlen(cmd) + 2;
        char *full = malloc(len);
        if (!full) { dir = strtok_r(NULL, ":", &saveptr); continue; }
        snprintf(full, len, "%s/%s", dir, cmd);
        if (access(full, X_OK) == 0) { free(p); return full; }
        free(full);
        dir = strtok_r(NULL, ":", &saveptr);
    }
    free(p);
    return NULL;
}

int builtin_which(char **args) {
    if (!args[1]) { fprintf(stderr, "which: missing operand\n"); return 1; }
    char *found = find_in_path(args[1]);
    if (found) { printf("%s\n", found); free(found); }
    else printf("%s not found\n", args[1]);
    return 1;
}

int builtin_jobs(char **args) {
    (void)args;
    jobs_print();
    return 1;
}

int builtin_fg(char **args) {
    if (!args[1]) { fprintf(stderr, "fg: missing job id\n"); return 1; }
    int id = atoi(args[1]);
    Job *j = jobs_find_by_id(id);
    if (!j) { fprintf(stderr, "fg: job not found: %d\n", id); return 1; }
    if (kill(j->pid, SIGCONT) != 0) {
        if (errno != ESRCH) perror("fg");
    }
    int status;
    pid_t ret = waitpid(j->pid, &status, 0);
    if (ret == -1) {
        if (errno != ECHILD) perror("waitpid");
    } else {
    }
    j->status = JOB_DONE;
    jobs_remove_done();
    return 1;
}

int builtin_bg(char **args) {
    if (!args[1]) { fprintf(stderr, "bg: missing job id\n"); return 1; }
    int id = atoi(args[1]);
    Job *j = jobs_find_by_id(id);
    if (!j) { fprintf(stderr, "bg: job not found: %d\n", id); return 1; }
    if (kill(j->pid, SIGCONT) != 0) perror("bg");
    else j->status = JOB_RUNNING;
    return 1;
}

int run_builtin(char **args) {
    if (!args[0]) return 1;
    if (strcmp(args[0], "cd") == 0) return builtin_cd(args);
    if (strcmp(args[0], "pwd") == 0) return builtin_pwd(args);
    if (strcmp(args[0], "ls") == 0) return builtin_ls(args);
    if (strcmp(args[0], "mkdir") == 0) return builtin_mkdir(args);
    if (strcmp(args[0], "rmdir") == 0) return builtin_rmdir(args);
    if (strcmp(args[0], "touch") == 0) return builtin_touch(args);
    if (strcmp(args[0], "rm") == 0) return builtin_rm(args);
    if (strcmp(args[0], "cp") == 0) return builtin_cp(args);
    if (strcmp(args[0], "mv") == 0) return builtin_mv(args);
    if (strcmp(args[0], "cat") == 0) return builtin_cat(args);
    if (strcmp(args[0], "echo") == 0) return builtin_echo(args);
    if (strcmp(args[0], "help") == 0) return builtin_help(args);
    if (strcmp(args[0], "exit") == 0) return builtin_exit(args);
    if (strcmp(args[0], "history") == 0) return builtin_history(args);
    if (strcmp(args[0], "clear") == 0) return builtin_clear(args);
    if (strcmp(args[0], "which") == 0) return builtin_which(args);
    if (strcmp(args[0], "jobs") == 0) return builtin_jobs(args);
    if (strcmp(args[0], "fg") == 0) return builtin_fg(args);
    if (strcmp(args[0], "bg") == 0) return builtin_bg(args);
    return 1;
}

char **split_line(char *line, int *ntokens) {
    if (!line) { *ntokens = 0; return NULL; }
    int capacity = MAX_TOKENS;
    char **tokens = malloc(capacity * sizeof(char *));
    if (!tokens) return NULL;
    int count = 0;
    char *p = line;

    while (*p) {
        while (*p && (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r')) p++;
        if (!*p) break;

        char *start;
        if (*p == '\'' || *p == '"') {
            char quote = *p++;
            start = p;
            char *buf = malloc(strlen(p) + 1);
            if (!buf) { for (int i = 0; i < count; ++i) free(tokens[i]); free(tokens); return NULL; }
            char *b = buf;
            while (*p && *p != quote) {
                if (*p == '\\' && p[1] != '\0') {
                    p++;
                    *b++ = *p++;
                } else {
                    *b++ = *p++;
                }
            }
            *b = '\0';
            tokens[count++] = buf;
            if (*p == quote) p++;
        } else {
            char *buf = malloc(strlen(p) + 1);
            if (!buf) { for (int i = 0; i < count; ++i) free(tokens[i]); free(tokens); return NULL; }
            char *b = buf;
            while (*p && *p != ' ' && *p != '\t' && *p != '\n' && *p != '\r') {
                if (*p == '\\' && p[1] != '\0') { p++; *b++ = *p++; }
                else *b++ = *p++;
            }
            *b = '\0';
            tokens[count++] = buf;
        }

        if (count >= capacity - 1) {
            capacity *= 2;
            char **tmp = realloc(tokens, capacity * sizeof(char *));
            if (!tmp) {
                for (int i = 0; i < count; ++i) free(tokens[i]);
                free(tokens);
                return NULL;
            }
            tokens = tmp;
        }
    }
    tokens[count] = NULL;
    *ntokens = count;
    return tokens;
}

void free_tokens(char **tokens, int ntokens) {
    if (!tokens) return;
    for (int i = 0; i < ntokens; ++i) {
        if (tokens[i]) free(tokens[i]);
    }
    free(tokens);
}

void launch_external(char **args, int ntokens, int bg) {
    pid_t pid = fork();
    if (pid < 0) {
        perror("fork");
        return;
    }
    if (pid == 0) {
        signal(SIGINT, SIG_DFL);
        signal(SIGQUIT, SIG_DFL);
        if (setpgid(0, 0) < 0) {
        }
        if (execvp(args[0], args) < 0) {
            perror("exec");
            _exit(127);
        }
    } else {
        if (setpgid(pid, pid) < 0 && errno != EINVAL && errno != EPERM) {
        }
        if (bg) {
            char *cmdstr = build_cmd_from_tokens(args, ntokens);
            int jid = jobs_add(pid, cmdstr ? cmdstr : args[0]);
            if (cmdstr) free(cmdstr);
            if (jid >= 0) printf("[%d] %d\n", jid, (int)pid);
            else printf("[Background pid %d]\n", (int)pid);
        } else {
            int status;
            if (waitpid(pid, &status, 0) < 0) {
                if (errno != ECHILD) perror("waitpid");
            }
        }
    }
}

int main() {
    struct sigaction sa;
    sa.sa_handler = sigchld_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART | SA_NOCLDSTOP;
    if (sigaction(SIGCHLD, &sa, NULL) < 0) {
        perror("sigaction");
    }
    signal(SIGINT, SIG_IGN);

    history_init();
    jobs_init();

    char *line = NULL;
    size_t len = 0;
    while (1) {
        if (sigchld_flag) reap_children();

        char cwd[4096];
        if (getcwd(cwd, sizeof(cwd))) printf("%s$ ", cwd);
        else printf("$ ");
        fflush(stdout);

        ssize_t nread = getline(&line, &len, stdin);
        if (nread <= 0) { printf("\n"); break; }
        while (nread > 0 && (line[nread-1] == '\n' || line[nread-1] == '\r')) line[--nread] = '\0';
        if (nread == 0) continue;

        history_add(line);

        int ntokens = 0;
        char **tokens = split_line(line, &ntokens);
        if (!tokens) {
            fprintf(stderr, "tokenization failed\n");
            continue;
        }
        if (ntokens == 0) { free(tokens); continue; }

        int bg = 0;
        if (ntokens > 0 && strcmp(tokens[ntokens-1], "&") == 0) {
            bg = 1;
            free(tokens[--ntokens]);
            tokens[ntokens] = NULL;
        }

        if (tokens[0] && is_builtin(tokens[0])) {
            run_builtin(tokens);
        } else {
            launch_external(tokens, ntokens, bg);
        }

        free_tokens(tokens, ntokens);
    }

    free(line);
    history_free();
    jobs_free();
    return 0;
}