use core::mem::{self, offset_of};

use libc::{user, user_fpregs_struct, user_regs_struct, c_uint};

use registers_macro::{registers};

#[derive(Copy, Clone, Debug)]
pub enum RegisterFormat {
    UInt, DoubleFloat, LongDouble, Vector
}

#[derive(Copy, Clone, Debug)]
pub enum RegisterType {
    GeneralPurpose,
    GeneralPurposeSub,
    FloatingPoint,
    Debug
}

type DwarfId = i32;

#[derive(Clone, Debug)]
pub struct RegisterInfo {
    id: RegisterId,
    name: &'static str,
    dwarf_id: DwarfId,
    size: usize,
    offset: usize,
    ty: RegisterType,
    format: RegisterFormat
}

registers![
    gpr64(rax, 0),
    gpr64(rdx, 1),
    gpr64(rcx, 2),
    gpr64(rbx, 3),
    gpr64(rsi, 4),
    gpr64(rdi, 5),
    gpr64(rbp, 6),
    gpr64(rsp, 7),
    gpr64(r8, 8),
    gpr64(r9, 9),
    gpr64(r10, 10),
    gpr64(r11, 11),
    gpr64(r12, 12),
    gpr64(r13, 13),
    gpr64(r14, 14),
    gpr64(r15, 15),
    gpr64(rip, 16),
    gpr64(eflags, 49),
    gpr64(cs, 51),
    gpr64(fs, 54),
    gpr64(gs, 55),
    gpr64(ss, 52),
    gpr64(ds, 53),
    gpr64(es, 50),
    gpr64(orig_rax, -1),

    gpr32(eax, rax), gpr32(edx, rdx),
    gpr32(ecx, rcx), gpr32(ebx, rbx),
    gpr32(esi, rsi), gpr32(edi, rdi),
    gpr32(ebp, rbp), gpr32(esp, rsp),
    gpr32(r8d, r8), gpr32(r9d, r9),
    gpr32(r10d, r10), gpr32(r11d, r11),
    gpr32(r12d, r12), gpr32(r13d, r13),
    gpr32(r14d, r14), gpr32(r15d, r15),

    gpr16(ax, rax), gpr16(dx, rdx),
    gpr16(cx, rcx), gpr16(bx, rbx),
    gpr16(si, rsi), gpr16(di, rdi),
    gpr16(bp, rbp), gpr16(sp, rsp),
    gpr16(r8w, r8), gpr16(r9w, r9),
    gpr16(r10w, r10), gpr16(r11w, r11),
    gpr16(r12w, r12), gpr16(r13w, r13),
    gpr16(r14w, r14), gpr16(r15w, r15),

    gpr8h(ah, rax), gpr8h(dh, rdx),
    gpr8h(ch, rcx), gpr8h(bh, rbx),

    gpr8l(al, rax), gpr8l(dl, rdx),
    gpr8l(cl, rcx), gpr8l(bl, rbx),
    gpr8l(sil, rsi), gpr8l(dil, rdi),
    gpr8l(bpl, rbp), gpr8l(spl, rsp),
    gpr8l(r8b, r8), gpr8l(r9b, r9),
    gpr8l(r10b, r10), gpr8l(r11b, r11),
    gpr8l(r12b, r12), gpr8l(r13b, r13),
    gpr8l(r14b, r14), gpr8l(r15b, r15),

    fpr(fcw, 65, cwd),
    fpr(fsw, 66, swd),
    fpr(ftw, -1, ftw),
    fpr(fop, -1, fop),
    fpr(frip, -1, rip),
    fpr(frdp, -1, rdp),
    fpr(mxcsr, 64, mxcsr),
    fpr(mxcsrmask, -1, mxcr_mask),

    fp_st(0), fp_st(1), fp_st(2), fp_st(3),
    fp_st(4), fp_st(5), fp_st(6), fp_st(7),

    fp_mm(0), fp_mm(1), fp_mm(2), fp_mm(3),
    fp_mm(4), fp_mm(5), fp_mm(6), fp_mm(7),

    fp_xmm(0), fp_xmm(1), fp_xmm(2), fp_xmm(3),
    fp_xmm(4), fp_xmm(5), fp_xmm(6), fp_xmm(7),
    fp_xmm(8), fp_xmm(9), fp_xmm(10), fp_xmm(11),
    fp_xmm(12), fp_xmm(13), fp_xmm(14), fp_xmm(15),

    dr(0), dr(1), dr(2), dr(3),
    dr(4), dr(5), dr(6), dr(7)
];