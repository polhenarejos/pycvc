# -*- coding: utf-8 -*-
"""
/*
 * This file is part of the pyCVC distribution (https://github.com/polhenarejos/pycvc).
 * Copyright (c) 2022 Pol Henarejos.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, version 3.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */
"""

from cvc.utils import to_bytes
from cvc import oid

class Type:
    CVCA = 3
    DV_domestic = 2
    DV_foreign = 1
    Terminal = 0

    __chat = 0

    def __init__(self, role, _args, kwargs):
        self.role = role
        for attr in _args:
            setattr(self, attr, kwargs.get(attr, 0))

    def to_bytes(self):
        total = len(self._args)
        x = self.fields()
        x = x + self.role * 2**(total)
        x |= self.__chat
        return x.to_bytes((total + 7) // 8, 'big')

    def chat(self, chat):
        if (chat):
            if (isinstance(chat, str)):
                chat = int(chat, 2)
            self.__chat = chat

    def from_bytes(o, chat):
        for s in Type.__subclasses__():
            if (s.OID == o):
                nargs = len(s._args)
                chat = int.from_bytes(chat, 'big')
                kwargs = {attr: (chat >> (nargs - ix - 1)) & 1 for ix, attr in enumerate(s._args)}
                return s(chat >> nargs, **kwargs)
        raise Exception('Unknown type')

    def fields_str(self):
        fields = [bit for ix, bit in enumerate(self._args) if getattr(self, bit, 0) == 1]
        return ", ".join(fields)

    def fields(self):
        nargs = len(self._args)
        x = 0
        for ix, attr in enumerate(self._args):
            x = x + 2**(nargs-ix-1) * getattr(self, attr, 0)
        return x

    def role_str(self):
        if (self.role == Type.CVCA):
            return 'CA'
        elif (self.role == Type.DV_domestic):
            return 'DV domestic'
        elif (self.role == Type.DV_foreign):
            return 'DV foreign'
        elif (self.role == Type.Terminal):
            return 'Terminal'
        return 'Unknown type'

class TypeIS(Type):
    OID = oid.ID_IS
    name = 'TypeIS'
    _args = ('rfu5', 'rfu4', 'rfu3', 'rfu2', 'read_iris', 'read_fingerprint')
    def __init__(self, role, **kwargs):
        super().__init__(role, self._args, kwargs)

class TypeAT(Type):
    OID = oid.ID_AT
    name = 'TypeAT'
    _args = ('write_dg17', 'write_dg18', 'write_dg19', 'write_dg20', 'write_dg21', 'write_dg22', 'rfu31', 'psa', 'read_dg22', 'read_dg21', 'read_dg20', 'read_dg19', 'read_dg18', 'read_dg17', 'read_dg16', 'read_dg15', 'read_dg14', 'read_dg13', 'read_dg12', 'read_dg11', 'read_dg10', 'read_dg9', 'read_dg8', 'read_dg7', 'read_dg6', 'read_dg5', 'read_dg4', 'read_dg3', 'read_dg2', 'read_dg1', 'install_qual_cert', 'install_cert', 'pin_management', 'can_allowed', 'privileged', 'rid', 'verify_community', 'verify_age')
    def __init__(self, role, **kwargs):
        super().__init__(role, self._args, kwargs)

class TypeST(Type):
    OID = oid.ID_ST
    name = 'TypeST'
    _args = ('rfu5', 'rfu4', 'rfu3', 'rfu2', 'gen_qual_sig', 'gen_sig')
    def __init__(self, role, **kwargs):
        super().__init__(role, self._args, kwargs)
