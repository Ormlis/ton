/*
    This file is part of TON Blockchain Library.

    TON Blockchain Library is free software: you can redistribute it and/or modify
    it under the terms of the GNU Lesser General Public License as published by
    the Free Software Foundation, either version 2 of the License, or
    (at your option) any later version.

    TON Blockchain Library is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Lesser General Public License for more details.

    You should have received a copy of the GNU Lesser General Public License
    along with TON Blockchain Library.  If not, see <http://www.gnu.org/licenses/>.

    Copyright 2017-2020 Telegram Systems LLP
*/
#pragma once

#include "ton/ton-types.h"
#include "vm/cells/Cell.h"

namespace ton::validator {

// Roots retained by the collator or transport decoder for local reuse. The hashes
// bind them to the serialized BOCs; this context is not part of BlockCandidate.
struct CandidateRoots {
  FileHash block_file_hash;
  FileHash collated_file_hash;
  td::Ref<vm::Cell> block_root;
  std::vector<td::Ref<vm::Cell>> collated_roots;
};

}  // namespace ton::validator
