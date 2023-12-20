# -*- coding: utf-8 -*-

import json
import time

from typing import List

#Взаимствовано со старого проекта (начало)
class AbstractModel:
    TABLE_NAME = None
    SECRET_FIELDS = []

    def __init__(self, **kwargs):
        object.__setattr__(self, 'fields', kwargs)

    def __getattr__(self, item):
        return self.fields[item] if item in self.fields.keys() else None

    def __setattr__(self, key, value):
        self.fields[key] = value

    def update_fields(self, fields: dict):
        object.__getattribute__(self, 'fields').update(fields)

    def _get_keys(self):
        return f"({', '.join(self.fields.keys())})"

    def add(self, cur):
        sql = f"INSERT INTO `{self.TABLE_NAME}` {self._get_keys()} VALUES ({', '.join(['%s'] * len(self.fields))});"
        cur.execute(
            sql,
            tuple(self.fields.values()))
        self.fields['id'] = cur.lastrowid

    def get_one(self,
                cur,
                limit: int = None,
                offset: int = 0,
                order: str = None) -> bool:
        sql = f"SELECT * FROM `{self.TABLE_NAME}`"
        if len(self.fields) > 0:
            sql += f" WHERE {' AND '.join(f'`{k}`=%s' for k in self.fields.keys())}"

        if order is not None:
            sql += f" {order}"

        if limit is not None:
            sql += f" LIMIT {offset}, {limit}"

        cur.execute(sql, tuple(self.fields.values()))

        f = cur.fetchone()
        if f is not None:
            self.fields.update(**dict(f))
            return True
        return False

    def get_many(self,
                 cur,
                 limit: int = None,
                 offset: int = 0,
                 order: str = None) -> List[__name__]:
        sql = f"SELECT * FROM `{self.TABLE_NAME}`"
        if self.fields:
            sql += f" WHERE {' AND '.join(f'`{k}`=%s' for k in self.fields.keys())}"

        if order is not None:
            sql += f" {order}"

        if limit is not None:
            sql += f" LIMIT {offset}, {limit}"

        cur.execute(sql, tuple(self.fields.values()))

        return [self.__class__(**dict(fields)) for fields in cur.fetchall()]

    def delete(self, cur):
        return cur.execute(
            f"DELETE FROM `{self.TABLE_NAME}` WHERE {' AND '.join(f'`{k}`=%s' for k in self.fields.keys())};",
            tuple(self.fields.values())) > 0

    def update(self, cur):
        return cur.execute(f"UPDATE `{self.TABLE_NAME}` SET {', '.join(f'`{k}`=%s' for k in self.fields.keys())} "
                           f"WHERE `id` = {self.id};",
                           tuple(self.fields.values()))

    def __str__(self):
        return str(self.serialize(include_secret_fields=True))

    def serialize(self, include_secret_fields=False):
        if include_secret_fields:
            return self.fields
        return {k: v for k, v in self.fields.items() if k not in self.SECRET_FIELDS}

    def to_json(self, **kwargs):
        return json.dumps(self.serialize(**kwargs))
#Взаимствовано со старого проекта (конец)

class User(AbstractModel):
    TABLE_NAME = 'users'
    SECRET_FIELDS = ['password_hash']


class Message(AbstractModel):
    TABLE_NAME = 'messages'


class ChatPublicKey(AbstractModel):
    TABLE_NAME = 'public_keys'


class SessionKey(AbstractModel):
    TABLE_NAME = 'session_keys'
