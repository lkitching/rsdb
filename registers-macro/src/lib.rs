use proc_macro::{TokenStream, TokenTree, Ident, Group, Delimiter, Punct, Spacing, Span, Literal};
use std::convert::{AsRef};
use std::num::{NonZeroU8};

//NOTE: This must match the definition in the librsdb::register module!
type DwarfId = i32;

trait RegisterDefinition {
    fn name(&self) -> &str;
    fn register_info(&self) -> RegisterInfoDef;
}

trait AsTokens {
    fn as_tokens(&self) -> TokenStream;
}

impl AsTokens for Box<dyn AsTokens> {
    fn as_tokens(&self) -> TokenStream {
        self.as_ref().as_tokens()
    }
}

impl AsTokens for u8 {
    fn as_tokens(&self) -> TokenStream {
        TokenTree::Literal(Literal::u8_unsuffixed(*self)).into()
    }
}

impl AsTokens for u32 {
    fn as_tokens(&self) -> TokenStream {
        TokenTree::Literal(Literal::u32_unsuffixed(*self)).into()
    }
}

impl AsTokens for i32 {
    fn as_tokens(&self) -> TokenStream {
        TokenTree::Literal(Literal::i32_unsuffixed(*self)).into()
    }
}

impl AsTokens for usize {
    fn as_tokens(&self) -> TokenStream {
        TokenTree::Literal(Literal::usize_unsuffixed(*self)).into()
    }
}

impl AsTokens for String {
    fn as_tokens(&self) -> TokenStream {
        TokenTree::Literal(Literal::string(self.as_str())).into()
    }
}

struct EnumExpr {
    enum_name: String,
    constructor: String
}

impl AsTokens for EnumExpr {
    fn as_tokens(&self) -> TokenStream {
        TokenStream::from_iter(vec![
            ident(self.enum_name.as_str()),
            TokenTree::Punct(Punct::new(':', Spacing::Joint)),
            TokenTree::Punct(Punct::new(':', Spacing::Alone)),
            ident(self.constructor.as_str())
        ])
    }
}

struct RegisterInfoDef {
    name: String,
    dwarf_id: DwarfId,
    size_expr: Box<dyn AsTokens>,
    offset_expr: Box<dyn AsTokens>,
    type_constructor: String,
    format_constructor: String
}

fn add_field_initialiser(tokens: &mut TokenStream, field_name: &str, init_expr: &impl AsTokens) {
    // append field initialiser to token stream i.e.
    // field: init,
    tokens.extend(vec![
        TokenTree::Ident(Ident::new(field_name, Span::call_site())),
        TokenTree::Punct(Punct::new(':', Spacing::Alone))
    ]);
    tokens.extend(init_expr.as_tokens());
    tokens.extend(vec![TokenTree::Punct(Punct::new(',', Spacing::Alone))]);
}

impl RegisterInfoDef {
    fn into_tokens(self) -> TokenStream {
        // RegisterInfo {
        //   id: RegisterId::{name},
        //   offset: offset_of!(user, regs) + offset_of!(user_regs_struct, {name})
        //   ...
        // }
        let mut initialiser_tokens = TokenStream::new();
        add_field_initialiser(&mut initialiser_tokens, "id", &EnumExpr { enum_name: String::from("RegisterId"), constructor: self.name.clone() });
        add_field_initialiser(&mut initialiser_tokens, "name", &self.name);
        add_field_initialiser(&mut initialiser_tokens, "dwarf_id", &self.dwarf_id);
        add_field_initialiser(&mut initialiser_tokens, "size", &self.size_expr);
        add_field_initialiser(&mut initialiser_tokens, "offset", &self.offset_expr);
        add_field_initialiser(&mut initialiser_tokens, "ty", &EnumExpr { enum_name: String::from("RegisterType"), constructor: self.type_constructor });
        add_field_initialiser(&mut initialiser_tokens, "format", &EnumExpr { enum_name: String::from("RegisterFormat"), constructor: self.format_constructor });

        TokenStream::from_iter(vec![
            TokenTree::Ident(Ident::new("RegisterInfo", Span::call_site())),
            TokenTree::Group(Group::new(Delimiter::Brace, initialiser_tokens))
        ])
    }
}

struct GPR64 {
    name: String,
    dwarf_id: i32
}

impl RegisterDefinition for GPR64 {
    fn name(&self) -> &str { self.name.as_str() }

    fn register_info(&self) -> RegisterInfoDef {
        RegisterInfoDef {
            name: self.name.clone(),
            dwarf_id: self.dwarf_id,
            size_expr: Box::new(8usize),
            offset_expr: Box::new(NestedOffset::user_nested_sub_field("regs", "user_regs_struct", self.name.as_str())),
            type_constructor: String::from("GeneralPurpose"),
            format_constructor: String::from("UInt")
        }
    }
}

struct InnerFieldOffset {
    field_offset: NestedOffset,
    inner_offset: NonZeroU8
}

impl AsTokens for InnerFieldOffset {
    fn as_tokens(&self) -> TokenStream {
        // (field_offset) + 1
        TokenStream::from_iter(vec![
            TokenTree::Group(Group::new(Delimiter::Parenthesis, self.field_offset.as_tokens())),
            TokenTree::Punct(Punct::new('+', Spacing::Alone)),
            TokenTree::Literal(Literal::u8_unsuffixed(self.inner_offset.get()))
        ])
    }
}

struct GPSub {
    name: String,
    super_name: String,
    size: u8,
    register_field_offset: Option<NonZeroU8>
}

impl GPSub {
    fn sub32(name: String, super_name: String) -> Self {
        Self { name, super_name, size: 4, register_field_offset: None }
    }

    fn sub16(name: String, super_name: String) -> Self {
        Self { name, super_name, size: 2, register_field_offset: None }
    }

    fn sub8h(name: String, super_name: String) -> Self {
        Self { name, super_name, size: 1, register_field_offset: NonZeroU8::new(1) }
    }

    fn sub8l(name: String, super_name: String) -> Self {
        Self { name, super_name, size: 1, register_field_offset: None }
    }
}

impl RegisterDefinition for GPSub {
    fn name(&self) -> &str {
        self.name.as_str()
    }

    fn register_info(&self) -> RegisterInfoDef {
        // sub registers are contained within the fields of the super register
        // most sub registers begin at the same address as the super register field, but are smaller in size (e.g. eax is the first 4 bytes of the 8-byte rax register)
        // the exception is the 8-bit 'h' registers which contain the upper 8-bits of the 16-bit sub registers (e.g. ah is the second byte of the 2-byte ax register)
        // these registers therefore exist at an offset (of 1 byte) from the start of the super register field within the user struct
        let field_offset = NestedOffset::gpr_offset(self.super_name.as_str());
        let offset_expr: Box<dyn AsTokens> = match self.register_field_offset {
            None => {
                Box::new(field_offset)
            },
            Some(fo) => {
                Box::new(InnerFieldOffset { field_offset, inner_offset: fo })
            }
        };

        RegisterInfoDef {
            name: self.name.clone(),
            dwarf_id: -1,
            size_expr: Box::new(self.size),
            offset_expr,
            type_constructor: String::from("GeneralPurposeSub"),
            format_constructor: String::from("UInt")
        }
    }
}

struct FPR {
    name: String,
    dwarf_id: i32,
    user_name: String
}

impl RegisterDefinition for FPR {
    fn name(&self) -> &str { self.name.as_str() }

    fn register_info(&self) -> RegisterInfoDef {
        RegisterInfoDef {
            name: self.name.clone(),
            dwarf_id: self.dwarf_id,
            size_expr: Box::new(SizeofField { struct_name: String::from("user_fpregs_struct"), field_name: self.user_name.clone() }),
            offset_expr: Box::new(NestedOffset::user_nested_sub_field("i387", "user_fpregs_struct", self.user_name.as_str())),
            type_constructor: String::from("FloatingPoint"),
            format_constructor: String::from("UInt")
        }
    }
}

struct FPST {
    name: String,
    number: u8
}

impl FPST {
    fn new(number: u8) -> Self {
        Self { name: format!("st{}", number), number }
    }
}

impl RegisterDefinition for FPST {
    fn name(&self) -> &str {
        self.name.as_str()
    }

    fn register_info(&self) -> RegisterInfoDef {
        RegisterInfoDef {
            name: self.name.clone(),
            dwarf_id: self.number as DwarfId + 33,
            size_expr: Box::new(16u8),
            offset_expr: Box::new(RegisterArrayOffset::fp_register("st_space", self.number)),
            type_constructor: String::from("FloatingPoint"),
            format_constructor: String::from("LongDouble")
        }
    }
}

struct FPMM {
    name: String,
    number: u8
}

impl FPMM {
    fn new(number: u8) -> Self {
        Self { name: format!("mm{}", number), number }
    }
}

impl RegisterDefinition for FPMM {
    fn name(&self) -> &str {
        self.name.as_str()
    }

    fn register_info(&self) -> RegisterInfoDef {
        RegisterInfoDef {
            name: self.name.clone(),
            dwarf_id: self.number as DwarfId + 41,
            size_expr: Box::new(8u8),
            offset_expr: Box::new(RegisterArrayOffset::fp_register("st_space", self.number)),
            type_constructor: String::from("FloatingPoint"),
            format_constructor: String::from("Vector")
        }
    }
}

struct FPXMM {
    name: String,
    number: u8
}

impl FPXMM {
    fn new(number: u8) -> Self {
        Self { name: format!("xmm{}", number), number }
    }
}

impl RegisterDefinition for FPXMM {
    fn name(&self) -> &str {
        self.name.as_str()
    }

    fn register_info(&self) -> RegisterInfoDef {
        RegisterInfoDef {
            name: self.name.clone(),
            dwarf_id: self.number as DwarfId + 17,
            size_expr: Box::new(16u8),
            offset_expr: Box::new(RegisterArrayOffset::fp_register("xmm_space", self.number)),
            type_constructor: String::from("FloatingPoint"),
            format_constructor: String::from("Vector")
        }
    }
}

struct DR {
    name: String,
    index: u8
}

impl DR {
    fn new(index: u8) -> Self {
        Self { name: format!("dr{}", index), index }
    }
}

impl RegisterDefinition for DR {
    fn name(&self) -> &str {
        self.name.as_str()
    }

    fn register_info(&self) -> RegisterInfoDef {
        RegisterInfoDef {
            name: self.name.clone(),
            dwarf_id: -1,
            size_expr: Box::new(8u8),
            offset_expr: Box::new(RegisterArrayOffset::debug_register(self.index)),
            type_constructor: String::from("Debug"),
            format_constructor: String::from("UInt")
        }
    }
}

struct RegisterArrayOffset {
    array_offset: NestedOffset,
    index: u8,
    register_size: u8
}

impl RegisterArrayOffset {
    fn fp_register(array_name: &str, index: u8) -> Self {
        // fp st registers are stored in an 'st_space' or an 'xmm_space' array within the user_fpregs struct
        // each register is 16 bytes so each one spans 4 elements of the array
        // so offset in struct is at number * 16 from the start of this member
        // see sys/user.h for definition
        // offset of array member can be found using nested offset expression i.e. (offset_of(user, i387) + offset_of(user_fpregs_struct, array_name))
        // add this token stream to a group then add the offset into the array
        // (offset_of(user, i387) + offset_of(user_fpregs_struct, array_name)) + (index * 16)
        let array_offset = NestedOffset::user_nested_sub_field("i387", "user_fpregs_struct", array_name);
        Self { array_offset, index, register_size: 16 }
    }

    fn debug_register(index: u8) -> Self {
        // debug registers are stored in the 'u_debugreg' array within the user struct
        // register are 8 bytes wide
        let array_offset = NestedOffset::new(vec![Offset { struct_name: String::from("user"), field_name: String::from("u_debugreg")}]);
        Self { array_offset, index, register_size: 8 }
    }
}

impl AsTokens for RegisterArrayOffset {
    fn as_tokens(&self) -> TokenStream {
        TokenStream::from_iter(vec![
            TokenTree::Group(Group::new(Delimiter::Parenthesis, self.array_offset.as_tokens())),
            TokenTree::Punct(Punct::new('+', Spacing::Alone)),
            TokenTree::Group(Group::new(Delimiter::Parenthesis, TokenStream::from_iter(vec![
                TokenTree::Literal(Literal::u8_unsuffixed(self.index)),
                TokenTree::Punct(Punct::new('*', Spacing::Alone)),
                TokenTree::Literal(Literal::u8_unsuffixed(self.register_size))
            ])))
        ])
    }
}

struct Offset {
    struct_name: String,
    field_name: String
}

impl AsTokens for Offset {
    fn as_tokens(&self) -> TokenStream {
        offset_of_tokens(self.struct_name.as_str(), self.field_name.as_str())
    }
}

struct NestedOffset {
    offsets: Vec<Offset>
}

impl NestedOffset {
    fn new(offsets: Vec<Offset>) -> Self {
        Self { offsets }
    }

    fn user_nested_sub_field(user_field: &str, sub_type_name: &str, sub_field: &str) -> Self {
        Self {
            offsets: vec![
                Offset { struct_name: String::from("user"), field_name: user_field.to_string() },
                Offset { struct_name: sub_type_name.to_string(), field_name: sub_field.to_string() }
            ]
        }
    }

    fn gpr_offset(register_name: &str) -> Self {
        // general purpose registers are at user::regs::{register_name}
        Self::user_nested_sub_field("regs", "user_regs_struct", register_name)
    }
}

fn offset_of_tokens(struct_name: &str, field_name: &str) -> TokenStream {
    // offset_of!(struct_name, field_name)
    TokenStream::from_iter(vec![
        ident("offset_of"),
        TokenTree::Punct(Punct::new('!', Spacing::Alone)),
        TokenTree::Group(Group::new(Delimiter::Parenthesis, TokenStream::from_iter(vec![
            ident(struct_name),
            TokenTree::Punct(Punct::new(',', Spacing::Alone)),
            ident(field_name)
        ])))
    ])
}

impl AsTokens for NestedOffset {
    fn as_tokens(&self) -> TokenStream {
        // offset_of!(struct1, field1) + offset_of!(struct2, field2) + .. + offset_of!(structN, fieldN)
        let mut tokens = Vec::new();
        let mut first = false;

        for offset in self.offsets.iter() {
            if first {
                tokens.push(TokenTree::Punct(Punct::new('+', Spacing::Alone)).into());
            }
            tokens.extend(offset_of_tokens(offset.struct_name.as_str(), offset.field_name.as_str()));
            first = true;
        }

        TokenStream::from_iter(tokens)
    }
}

struct SizeofField {
    struct_name: String,
    field_name: String
}

impl AsTokens for SizeofField {
    fn as_tokens(&self) -> TokenStream {
        // std::mem::size_of_val(&(unsafe { std::mem::zeroed::<struct_name>() }.field_name))
        TokenStream::from_iter(vec![
            ident("std"),
            TokenTree::Punct(Punct::new(':', Spacing::Joint)),
            TokenTree::Punct(Punct::new(':', Spacing::Alone)),
            ident("mem"),
            TokenTree::Punct(Punct::new(':', Spacing::Joint)),
            TokenTree::Punct(Punct::new(':', Spacing::Alone)),
            ident("size_of_val"),
            TokenTree::Group(Group::new(Delimiter::Parenthesis, TokenStream::from_iter(vec![
                TokenTree::Punct(Punct::new('&', Spacing::Alone)),
                TokenTree::Group(Group::new(Delimiter::Parenthesis, TokenStream::from_iter(vec![
                    ident("unsafe"),
                    TokenTree::Group(Group::new(Delimiter::Brace, TokenStream::from_iter(vec![
                        ident("std"),
                        TokenTree::Punct(Punct::new(':', Spacing::Joint)),
                        TokenTree::Punct(Punct::new(':', Spacing::Alone)),
                        ident("mem"),
                        TokenTree::Punct(Punct::new(':', Spacing::Joint)),
                        TokenTree::Punct(Punct::new(':', Spacing::Alone)),
                        ident("zeroed"),
                        TokenTree::Punct(Punct::new(':', Spacing::Joint)),
                        TokenTree::Punct(Punct::new(':', Spacing::Alone)),
                        TokenTree::Punct(Punct::new('<', Spacing::Alone)),
                        ident(self.struct_name.as_str()),
                        TokenTree::Punct(Punct::new('>', Spacing::Alone)),
                        TokenTree::Group(Group::new(Delimiter::Parenthesis, TokenStream::new()))
                    ]))),
                    TokenTree::Punct(Punct::new('.', Spacing::Alone)),
                    ident(self.field_name.as_str())
                ])))
            ])))
        ])
    }
}

fn ident(id: &str) -> TokenTree {
    TokenTree::Ident(Ident::new(id, Span::call_site()))
}

fn delimited_separated_by(delim: Delimiter, separator: char, tokens: impl IntoIterator<Item=TokenTree>) -> TokenTree {
    let mut first = false;
    let mut inner = Vec::new();

    for tok in tokens {
        if first {
            inner.push(TokenTree::Punct(Punct::new(separator, Spacing::Alone)));
        }
        inner.push(tok);
        first = true;
    }

    TokenTree::Group(Group::new(delim, TokenStream::from_iter(inner)))
}

fn define_register_id_tokens(registers: &Vec<Box<dyn RegisterDefinition>>) -> TokenStream {
    // #[derive(Copy,Clone,PartialEq,Eq,Debug)]
    // pub enum RegisterId {
    //   register1,
    //   register2,
    //   ...
    // }
    let mut tokens = TokenStream::new();

    let enum_def = vec![
        TokenTree::Punct(Punct::new('#', Spacing::Alone)),
        TokenTree::Group(Group::new(Delimiter::Bracket, TokenStream::from_iter(vec![
            TokenTree::Ident(Ident::new("derive", Span::call_site())),
            delimited_separated_by(Delimiter::Parenthesis, ',', vec![
                ident("Copy"),
                ident("Clone"),
                ident("PartialEq"),
                ident("Eq"),
                ident("Debug")
            ]),
        ]))),
        TokenTree::Ident(Ident::new("pub", Span::call_site())),
        TokenTree::Ident(Ident::new("enum", Span::call_site())),
        TokenTree::Ident(Ident::new("RegisterId", Span::call_site()))
    ];

    tokens.extend(enum_def);

    let mut constructor_tokens = TokenStream::new();

    for register in registers.iter() {
        let cts = vec![
            TokenTree::Ident(Ident::new(register.as_ref().name(), Span::call_site())),
            TokenTree::Punct(Punct::new(',', Spacing::Alone))
        ];
        constructor_tokens.extend(cts);
    }

    let constructor_group = vec![
        TokenTree::Group(Group::new(Delimiter::Brace, constructor_tokens))
    ];

    tokens.extend(constructor_group);

    tokens
}

fn register_infos_tokens(registers: &Vec<Box<dyn RegisterDefinition>>) -> TokenStream {
    // pub static REGISTER_INFOS: [RegisterInfo; N] = [
    //   RegisterInfo { id, name, dwarf_id, size, offset, type, format },
    //   RegisterInfo { ... },
    //   ...
    // ];
    let mut tokens = TokenStream::from_iter(vec![
        ident("pub"),
        ident("static"),
        ident("REGISTER_INFOS"),
        TokenTree::Punct(Punct::new(':', Spacing::Alone)),
        TokenTree::Group(Group::new(Delimiter::Bracket, TokenStream::from_iter(vec![
            ident("RegisterInfo"),
            TokenTree::Punct(Punct::new(';', Spacing::Alone)),
            TokenTree::Literal(Literal::usize_unsuffixed(registers.len()))
        ]))),
        TokenTree::Punct(Punct::new('=', Spacing::Alone))
    ]);

    let mut infos_tokens: Vec<TokenStream> = Vec::new();

    {
        let mut first = false;
        for register in registers.into_iter() {
            if first {
                infos_tokens.push(TokenTree::Punct(Punct::new(',', Spacing::Alone)).into());
            }

            let reg_info_def = register.register_info();
            infos_tokens.push(reg_info_def.into_tokens());
            first = true;
        }
    }

    tokens.extend(vec![
        TokenTree::Group(Group::new(Delimiter::Bracket, TokenStream::from_iter(infos_tokens))),
        TokenTree::Punct(Punct::new(';', Spacing::Alone))
    ]);

    tokens
}

fn parse_dwarf_id(iter: &mut impl Iterator<Item=TokenTree>) -> i32 {
    let f = iter.next().expect("Expected token for dwarf id");
    match f {
        TokenTree::Literal(lit) => {
            lit.to_string().parse().expect("Invalid numeric value for dwarf id")
        },
        TokenTree::Punct(p) => {
            if p.as_char() == '-' {
                // should be followed by a numeric literal
                let n = iter.next().expect("Expected token after '-' in dwarf id");
                if let TokenTree::Literal(lit) = n {
                    let i: i32 = lit.to_string().parse().expect("Invalid numeric value for dwarf id");
                    -i
                } else {
                    panic!("Expected literal after '-' in dwarf id");
                }
            } else {
                panic!("Expected '-' puncutation to start dwarf id");
            }
        },
        _ => { panic!("Expected '-' or numeric literal for dwarf id"); }
    }
}

fn parse_literal(tokens: &mut impl Iterator<Item=TokenTree>, context: &str) -> String {
    let token = tokens.next().expect(&format!("Expected literal token {}", context));
    match token {
        TokenTree::Literal(lit) => {
            lit.to_string()
        },
        _ => { panic!("Expected literal {}", context); }
    }
}

fn parse_u8(tokens: &mut impl Iterator<Item=TokenTree>, context: &str) -> u8 {
    let lit = parse_literal(tokens, context);
    lit.parse().expect(&format!("Invalid u8 literal {}", context))
}

fn expect_ident(token: TokenTree, context: &str) -> String {
    match token {
        TokenTree::Ident(ident) => {
            ident.to_string()
        },
        _ => {
            panic!("Expected identifier {}", context)
        }
    }
}

fn parse_ident(tokens: &mut impl Iterator<Item=TokenTree>, context: &str) -> String {
    let tok = tokens.next().expect(&format!("Expected ident token {}", context));
    expect_ident(tok, context)
}

fn expect_punct(token: TokenTree, context: &str) -> char {
    match token {
        TokenTree::Punct(p) => {
            // check spacing type?
            p.as_char()
        },
        _ => {
            panic!("Expected punctuation {}", context)
        }
    }
}

fn consume_punct(tokens: &mut impl Iterator<Item=TokenTree>, expected: char, context: &str) {
    let token = tokens.next().expect(&format!("Expected {} token", expected));
    let punct_char = expect_punct(token, context);
    if punct_char != expected {
        panic!("Expected '{}', got '{}' {}", expected, punct_char, context);
    }
}

fn parse_group(tokens: &mut impl Iterator<Item=TokenTree>, expected_delim: Delimiter, context: &str) -> TokenStream {
    let token = tokens.next().expect(&format!("Expected group token {}", context));
    match token {
        TokenTree::Group(group) => {
            if group.delimiter() == expected_delim {
                group.stream()
            } else {
                panic!("Expected {:?} delimiter for group, got {:?} {}", expected_delim, group.delimiter(), context)
            }
        },
        _ => {
            panic!("Expected group token {}", context)
        }
    }
}

fn expect_end(tokens: &mut impl Iterator<Item=TokenTree>, context: &str) {
    if tokens.next().is_some() {
        panic!("Expected end of tokens {}", context);
    }
}

struct SubRegister {
    name: String,
    super_name: String
}

fn parse_sub_register(tokens: &mut impl Iterator<Item=TokenTree>, sub_register_type: &str) -> SubRegister {
    let name = parse_ident(tokens, "register name");

    // skip , separator
    consume_punct(tokens, ',', format!("after {} register name", sub_register_type).as_str());

    let super_name = parse_ident(tokens, "super register name");

    expect_end(tokens, format!("After {} super register name", sub_register_type).as_str());

    SubRegister { name, super_name }
}

#[proc_macro]
pub fn registers(tokens: TokenStream) -> TokenStream {
    let mut defs: Vec<Box<dyn RegisterDefinition>> = Vec::new();

    let mut tok_iter = tokens.into_iter();

    while let Some(token_tree) = tok_iter.next() {
        let ident = expect_ident(token_tree, "at start of register definition");
        let mut def_tokens = parse_group(&mut tok_iter, Delimiter::Parenthesis, "following register type").into_iter();

        match ident.as_str() {
            "gpr64" => {
                let name = parse_ident(&mut def_tokens, "register name");

                // skip , separator
                consume_punct(&mut def_tokens, ',', "after GP64 register name");

                let dwarf_id = parse_dwarf_id(&mut def_tokens);

                expect_end(&mut def_tokens, "After GP dwarf id");

                defs.push(Box::new(GPR64 { name, dwarf_id }));
            },
            "gpr32" => {
                let SubRegister { name, super_name } = parse_sub_register(&mut def_tokens, "GP32");
                defs.push(Box::new(GPSub::sub32(name, super_name)));
            },
            "gpr16" => {
                let SubRegister { name, super_name } = parse_sub_register(&mut def_tokens, "GP16");
                defs.push(Box::new(GPSub::sub16(name, super_name)));
            },
            "gpr8h" => {
                let SubRegister { name, super_name } = parse_sub_register(&mut def_tokens, "GP8H");
                defs.push(Box::new(GPSub::sub8h(name, super_name)));
            }
            "gpr8l" => {
                let SubRegister { name, super_name } = parse_sub_register(&mut def_tokens, "GP8L");
                defs.push(Box::new(GPSub::sub8l(name, super_name)));
            }
            "fpr" => {
                let name= parse_ident(&mut def_tokens, "register name");

                // skip , separator
                consume_punct(&mut def_tokens, ',', "after FP register name");

                let dwarf_id = parse_dwarf_id(&mut def_tokens);

                // skip , separator
                consume_punct(&mut def_tokens, ',', "after FP dwarf id");

                let user_name = parse_ident(&mut def_tokens, "FP register user name");

                expect_end(&mut def_tokens, "After FP user name");

                defs.push(Box::new(FPR { name, dwarf_id, user_name }));
            }
            "fp_st" => {
                let number = parse_u8(&mut def_tokens, "FP ST number");
                expect_end(&mut def_tokens, "After FP ST number");

                defs.push(Box::new(FPST::new(number)));
            },
            "fp_mm" => {
                let number = parse_u8(&mut def_tokens, "FP MM number");
                expect_end(&mut def_tokens, "After FP MM number");

                defs.push(Box::new(FPMM::new(number)));
            },
            "fp_xmm" => {
                let number = parse_u8(&mut def_tokens, "FP XMM number");
                expect_end(&mut def_tokens, "After FP XMM number");

                defs.push(Box::new(FPXMM::new(number)));
            }
            "dr" => {
                let number = parse_u8(&mut def_tokens, "Debug register number");
                expect_end(&mut def_tokens, "After debug register number");

                defs.push(Box::new(DR::new(number)));
            }
            s => {
                panic!("Unknown register type {}", s);
            }
        }

        // consume separator if one exists
        if let Some(sep_tok) = tok_iter.next() {
            let sep = expect_punct(sep_tok, "after register definition");
            if sep != ',' {
                panic!("Expected , separator after register definition");
            }
        }
    }

    let mut output = TokenStream::new();
    output.extend(define_register_id_tokens(&defs));
    output.extend(register_infos_tokens(&defs));

    output
}

type SyscallId = u64;
struct Syscall {
    id: SyscallId,
    name: String,
}

fn parse_syscall_id(tokens: &mut impl Iterator<Item=TokenTree>, context: &str) -> SyscallId {
    let lit = parse_literal(tokens, context);
    lit.parse().expect(&format!("Invalid u8 literal {}", context))
}

fn generate_syscall_type(calls: &[Syscall]) -> TokenStream {
    // #[derive(Copy,Clone,PartialEq,Eq,Debug,Hash)]
    // pub enum SyscallType {
    //   syscall1,
    //   syscall2,
    //   ...
    // }
    let mut tokens = TokenStream::new();

    let enum_def = vec![
        TokenTree::Punct(Punct::new('#', Spacing::Alone)),
        TokenTree::Group(Group::new(Delimiter::Bracket, TokenStream::from_iter(vec![
            TokenTree::Ident(Ident::new("derive", Span::call_site())),
            delimited_separated_by(Delimiter::Parenthesis, ',', vec![
                ident("Copy"),
                ident("Clone"),
                ident("PartialEq"),
                ident("Eq"),
                ident("Debug"),
                ident("Hash")
            ]),
        ]))),
        TokenTree::Ident(Ident::new("pub", Span::call_site())),
        TokenTree::Ident(Ident::new("enum", Span::call_site())),
        TokenTree::Ident(Ident::new("SyscallType", Span::call_site()))
    ];

    tokens.extend(enum_def);

    let mut constructor_tokens = TokenStream::new();

    for syscall in calls.iter() {
        let cts = vec![
            TokenTree::Ident(Ident::new(syscall.name.as_str(), Span::call_site())),
            TokenTree::Punct(Punct::new(',', Spacing::Alone))
        ];
        constructor_tokens.extend(cts);
    }

    let constructor_group = vec![
        TokenTree::Group(Group::new(Delimiter::Brace, constructor_tokens))
    ];

    tokens.extend(constructor_group);

    tokens
}

fn generate_syscall_type_fromstr(calls: &[Syscall]) -> TokenStream {
    // impl std::str::FromStr for SyscallType {
    //  type Err = ();
    //  fn from_str(s: &str) -> Result<Self, Self::Err> {
    //    match s {
    //      "name1" => Ok(Self::name1),
    //      "name2" => Ok(Self::name2),
    //      ...
    //      _ => Err(())
    //   }
    // }

    let matches = {
        let mut tokens = TokenStream::new();
        for call in calls.iter() {
            let match_toks = vec![
                TokenTree::Literal(Literal::string(call.name.as_str())),
                TokenTree::Punct(Punct::new('=', Spacing::Joint)),
                TokenTree::Punct(Punct::new('>', Spacing::Alone)),
                ident("Ok"),
                TokenTree::Group(Group::new(Delimiter::Parenthesis, TokenStream::from_iter(vec![
                    ident("Self"),
                    TokenTree::Punct(Punct::new(':', Spacing::Joint)),
                    TokenTree::Punct(Punct::new(':', Spacing::Alone)),
                    ident(call.name.as_str())
                ]))),
                TokenTree::Punct(Punct::new(',', Spacing::Alone))
            ];
            tokens.extend(match_toks);
        }

        // add catch-all arm for anything else
        tokens.extend(vec![
            ident("_"),
            TokenTree::Punct(Punct::new('=', Spacing::Joint)),
            TokenTree::Punct(Punct::new('>', Spacing::Alone)),
            ident("Err"),
            TokenTree::Group(Group::new(Delimiter::Parenthesis, TokenStream::from_iter(vec![
                TokenTree::Group(Group::new(Delimiter::Parenthesis, TokenStream::new()))
            ])))
        ]);

        tokens
    };

    let from_str_tokens = vec![
        ident("fn"),
        ident("from_str"),
        TokenTree::Group(Group::new(Delimiter::Parenthesis, TokenStream::from_iter(vec![
            ident("s"),
            TokenTree::Punct(Punct::new(':', Spacing::Alone)),
            TokenTree::Punct(Punct::new('&', Spacing::Alone)),
            ident("str")
        ]))),
        TokenTree::Punct(Punct::new('-', Spacing::Joint)),
        TokenTree::Punct(Punct::new('>', Spacing::Alone)),
        ident("Result"),
        TokenTree::Punct(Punct::new('<', Spacing::Alone)),
        ident("Self"),
        TokenTree::Punct(Punct::new(',', Spacing::Alone)),
        ident("Self"),
        TokenTree::Punct(Punct::new(':', Spacing::Joint)),
        TokenTree::Punct(Punct::new(':', Spacing::Alone)),
        ident("Err"),
        TokenTree::Punct(Punct::new('>', Spacing::Alone)),
        TokenTree::Group(Group::new(Delimiter::Brace, TokenStream::from_iter(vec![
            ident("match"),
            ident("s"),
            TokenTree::Group(Group::new(Delimiter::Brace, matches))
        ])))
    ];

    let impl_tokens = {
        let mut inner_tokens = TokenStream::from_iter(vec![
            ident("type"),
            ident("Err"),
            TokenTree::Punct(Punct::new('=', Spacing::Alone)),
            TokenTree::Group(Group::new(Delimiter::Parenthesis, TokenStream::new())),
            TokenTree::Punct(Punct::new(';', Spacing::Alone))
        ]);
        inner_tokens.extend(from_str_tokens);

        TokenStream::from_iter(vec![
            ident("impl"),
            ident("std"),
            TokenTree::Punct(Punct::new(':', Spacing::Joint)),
            TokenTree::Punct(Punct::new(':', Spacing::Alone)),
            ident("str"),
            TokenTree::Punct(Punct::new(':', Spacing::Joint)),
            TokenTree::Punct(Punct::new(':', Spacing::Alone)),
            ident("FromStr"),
            ident("for"),
            ident("SyscallType"),
            TokenTree::Group(Group::new(Delimiter::Brace, inner_tokens))
        ])
    };

    impl_tokens
}

fn generate_syscall_impl(calls: &[Syscall]) -> TokenStream {
    // impl Syscall {
    //  pub fn from_id(id: u64) -> Result<Self, ()> {
    //    match id {
    //      id1 => Ok(Self::name1),
    //      id2 => Ok(Self::name2),
    //      ...
    //      _ => Err(())
    //    }
    //   }
    // }
    let matches = {
        let mut matches = TokenStream::new();

        for call in calls.iter() {
            let match_tokens = TokenStream::from_iter(vec![
                TokenTree::Literal(Literal::u64_unsuffixed(call.id)),
                TokenTree::Punct(Punct::new('=', Spacing::Joint)),
                TokenTree::Punct(Punct::new('>', Spacing::Alone)),
                ident("Ok"),
                TokenTree::Group(Group::new(Delimiter::Parenthesis, TokenStream::from_iter(vec![
                    ident("Self"),
                    TokenTree::Punct(Punct::new(':', Spacing::Joint)),
                    TokenTree::Punct(Punct::new(':', Spacing::Alone)),
                    ident(call.name.as_str())
                ]))),
                TokenTree::Punct(Punct::new(',', Spacing::Alone))
            ]);
            matches.extend(match_tokens);
        }

        // add catch-all arm for anything else
        matches.extend(vec![
            ident("_"),
            TokenTree::Punct(Punct::new('=', Spacing::Joint)),
            TokenTree::Punct(Punct::new('>', Spacing::Alone)),
            ident("Err"),
            TokenTree::Group(Group::new(Delimiter::Parenthesis, TokenStream::from_iter(vec![
                TokenTree::Group(Group::new(Delimiter::Parenthesis, TokenStream::new()))
            ])))
        ]);

        matches
    };

    let from_id_tokens = TokenStream::from_iter(vec![
        ident("pub"),
        ident("fn"),
        ident("from_id"),
        TokenTree::Group(Group::new(Delimiter::Parenthesis, TokenStream::from_iter(vec![
            ident("id"),
            TokenTree::Punct(Punct::new(':', Spacing::Alone)),
            ident("u64")
        ]))),
        TokenTree::Punct(Punct::new('-', Spacing::Joint)),
        TokenTree::Punct(Punct::new('>', Spacing::Alone)),
        ident("Result"),
        TokenTree::Punct(Punct::new('<', Spacing::Alone)),
        ident("Self"),
        TokenTree::Punct(Punct::new(',', Spacing::Alone)),
        TokenTree::Group(Group::new(Delimiter::Parenthesis, TokenStream::new())),
        TokenTree::Punct(Punct::new('>', Spacing::Alone)),
        TokenTree::Group(Group::new(Delimiter::Brace, TokenStream::from_iter(vec![
            ident("match"),
            ident("id"),
            TokenTree::Group(Group::new(Delimiter::Brace, matches))
        ])))
    ]);

    TokenStream::from_iter(vec![
        ident("impl"),
        ident("SyscallType"),
        TokenTree::Group(Group::new(Delimiter::Brace, from_id_tokens))
    ])
}

#[proc_macro]
pub fn syscalls(tokens: TokenStream) -> TokenStream {
    let mut calls = Vec::new();
    let mut tok_iter = tokens.into_iter();

    while let Some(token_tree) = tok_iter.next() {
        let ident = expect_ident(token_tree, "Expected syscall definition");
        assert_eq!("call", ident, "Expected 'call' literal");

        let mut call_tokens = parse_group(&mut tok_iter, Delimiter::Parenthesis, "following 'call'").into_iter();
        let name = parse_ident(&mut call_tokens, "syscall name");
        consume_punct(&mut call_tokens, ',', "after syscall name");
        let id = parse_syscall_id(&mut call_tokens, "after syscall name");
        expect_end(&mut call_tokens, "after syscall id");

        calls.push(Syscall { id, name });

        // consume ',' separator if one exists
        if let Some(tok) = tok_iter.next() {
            expect_punct(tok, "after call definition");
        }
    }

    let mut output = TokenStream::new();
    output.extend(generate_syscall_type(calls.as_slice()));
    output.extend(generate_syscall_type_fromstr(calls.as_slice()));
    output.extend(generate_syscall_impl(calls.as_slice()));

    output
}