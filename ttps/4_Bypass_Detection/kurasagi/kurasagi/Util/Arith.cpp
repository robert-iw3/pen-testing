/*
 * @file Arith.cpp
 * @brief Implementation of Arith.hpp
 */

#include "Arith.hpp"

BOOLEAN IsCollapsing(ULONG64 v1Start, ULONG64 v1End, ULONG64 v2Start, ULONG64 v2End) {
	return v1End >= v2Start && v2End >= v1Start;
}