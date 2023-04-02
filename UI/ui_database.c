#include <dlfcn.h>
#include <fcntl.h>
#include <ncurses.h>
#include <string.h>
#include <stdlib.h>
#include <ndbm.h>

typedef struct {
    char *key;
    char *value;
} Object;

void init_ncurses(void);

_Noreturn void display_results(DBM *db);

Object *load_object(DBM *db, datum *id);

int main(__attribute__((unused)) int argc, char *argv[]) {
    // connect to the db and get the values
    DBM * db = dbm_open("webdatabase", O_CREAT | O_RDWR, 0666);
    if (!db) {
        fprintf(stderr, "Failed to open database.\n");
    }
    init_ncurses();
    display_results(db);
}

void init_ncurses(void) {
    initscr();
    cbreak();
    noecho();
}

void display_results(DBM* db){
    while (1) {
        mvprintw(0, 0, "RESULTS FROM THE DATABASE");
        refresh();

        // Loop through all the keys in the database and display the corresponding values
        int y = 2;
        char *key_str;
        for (datum key = dbm_firstkey(db); key.dptr != NULL; key = dbm_nextkey(db)) {
            key.dptr[key.dsize] = '\0';
            Object *object = load_object(db, &key);
            if (object != NULL) {
                mvprintw(y++, 0, "Object key: %s Object value: %s", object->key, object->value);
                refresh();
                free(object->key);
                free(object->value);
                free(object);
            } else {
                mvprintw(y++, 0, "Key (%s) not found in the database", key_str);
                refresh();
            }
        }
        // Wait for user input before repeating
        mvprintw(y + 1, 0, "Press control C to exit.");
        refresh();
        getch();
    }
}


Object *load_object(DBM *db, datum *id) {
    Object *obj = malloc(sizeof(Object));
    datum  value;
    value = dbm_fetch(db, *id);
    if (value.dptr != NULL) {
        obj->key = strdup(id->dptr);
        obj->value = malloc(value.dsize + 1);
        memcpy(obj->value, value.dptr, value.dsize);
        obj->value[value.dsize] = '\0';
    } else {
        obj = NULL;
    }
    return obj;
}

