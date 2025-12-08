/*
 * LuaExpressionParser.cpp, part of VCMI engine
 *
 * Authors: listed in file AUTHORS in main folder
 *
 * License: GNU General Public License v2.0 or later
 * Full text of license available in license.txt file, in main folder
 *
 */
 
#include "StdInc.h"
#include "LuaExpressionParser.h"

#define LOG_ERROR(...) do { \
    logGlobal->error(__VA_ARGS__); \
    std::abort(); \
} while(0)


using namespace std;

VCMI_LIB_NAMESPACE_BEGIN

Tokenizer::Tokenizer(std::string expr) : expr_(std::move(expr)) {}

char Tokenizer::peek() const {
	return pos_ < expr_.size() ? expr_[pos_] : '\0';
}

void Tokenizer::advance() {
	if (pos_ < expr_.size())
		++pos_;
}

void Tokenizer::skipWhitespace() {
	while (isspace(peek())) advance();
}

Token Tokenizer::next() {
	skipWhitespace();
	if (pos_ >= expr_.size()) return { TokenType::End, "", pos_ };

	size_t start = pos_;
	char c = peek();

	if (isdigit(c) || c == '.') {
		bool has_dot = c == '.';
		advance();
		while (isdigit(peek()))
			advance();

		if (peek() == '.' && !has_dot) {
			advance();
			while (isdigit(peek())) advance();
		}
		return { TokenType::Number, expr_.substr(start, pos_ - start), start };
	}

	if (isalpha(c) || c == '_') {
		advance();
		while (isalnum(peek()) || peek() == '_') advance();

		std::string word = expr_.substr(start, pos_ - start);

		// 关键修改：将 and/or 识别为运算符
		if (word == "and" || word == "or") {
			return { TokenType::Operator, word, start };
		}
		return { TokenType::Identifier, word, start };
	}

	if (c == '(') {
		advance();
		return { TokenType::LeftParen, "(", start };
	}
	if (c == ')') {
		advance();
		return { TokenType::RightParen, ")", start };
	}
	if (c == ',') {
		advance();
		return { TokenType::Comma, ",", start };
	}

	std::string op(1, c);
	advance();
	if (c == '>' || c == '<' || c == '!' || c == '=') {
		if (peek() == '=') { // 检查下一个字符是否为'='
			op += '=';
			advance();
		}
	}
	else if (c == '~' && peek() == '=') {
		op += '=';
		advance();
	}
	else if ((c == '+' || c == '-' || c == '*' || c == '/' || c == '^') &&
		(peek() == c || (c == '*' && peek() == '*'))) {
		advance();
	}
	return { TokenType::Operator, op, start };
}

NumberNode::NumberNode(double value) : value_(value) {}

double NumberNode::eval(const std::unordered_map<std::string, double>&) const {
	return value_;
}

std::unique_ptr<ASTNode> NumberNode::clone() const {
	return std::make_unique<NumberNode>(value_);
}

VariableNode::VariableNode(std::string name) : name_(std::move(name)) {}

double VariableNode::eval(const std::unordered_map<std::string, double>& vars) const {
	auto it = vars.find(name_);
	if (it == vars.end()) {
		LOG_ERROR("Undefined variable: %s", name_.c_str());
	}
	return it->second;
}

std::unique_ptr<ASTNode> VariableNode::clone() const {
	return std::make_unique<VariableNode>(name_);
}

BinaryOpNode::BinaryOpNode(std::unique_ptr<ASTNode> left, char op, std::unique_ptr<ASTNode> right)
	: left_(std::move(left)), op_(op), right_(std::move(right)) {}

std::unique_ptr<ASTNode> BinaryOpNode::clone() const {
	return std::make_unique<BinaryOpNode>(
		left_->clone(),  // 深拷贝左子树
		op_,
		right_->clone()  // 深拷贝右子树
	);
}

double BinaryOpNode::eval(const std::unordered_map<std::string, double>& vars) const {
	double l = left_->eval(vars);
	double r = right_->eval(vars);
	switch (op_) {
	case '+': return l + r;
	case '-': return l - r;
	case '*': return l * r;
	case '/':
		if (r == 0) LOG_ERROR("Division by zero");
		return l / r;
	case '^': return pow(l, r);
	default: LOG_ERROR("Invalid operator: %c", op_);
	}
}

ComparisonNode::ComparisonNode(std::unique_ptr<ASTNode> left, std::string op, std::unique_ptr<ASTNode> right)
	: left_(std::move(left)), op_(std::move(op)), right_(std::move(right)) {}

double ComparisonNode::eval(const std::unordered_map<std::string, double>& vars) const {
	double l = left_->eval(vars);
	double r = right_->eval(vars);
	if (op_ == ">=") return l >= r;
	if (op_ == "<=") return l <= r;
	if (op_ == ">") return l > r;
	if (op_ == "<") return l < r;
	if (op_ == "==") return l == r;
	if (op_ == "~=") return l != r;
	LOG_ERROR("Invalid comparison operator: %s", op_.c_str());
}

ConditionalNode::ConditionalNode(
	std::unique_ptr<ASTNode> cond,
	std::unique_ptr<ASTNode> trueExpr,
	std::unique_ptr<ASTNode> falseExpr
) : cond_(std::move(cond)),
true_(std::move(trueExpr)),
false_(std::move(falseExpr)) {}

std::unique_ptr<ConditionalNode> ConditionalNode::create(
	std::unique_ptr<ASTNode> cond,
	std::unique_ptr<ASTNode> trueExpr,
	std::unique_ptr<ASTNode> falseExpr
) {
	if (!cond || !trueExpr || !falseExpr) {
		LOG_ERROR("Trying to create ConditionalNode with null children");
		std::abort();
	}
	return std::unique_ptr<ConditionalNode>(
		new ConditionalNode(std::move(cond), std::move(trueExpr), std::move(falseExpr))
	);
}

std::unique_ptr<ASTNode> ComparisonNode::clone() const {
	return std::make_unique<ComparisonNode>(
		left_->clone(),  // 深拷贝左子树
		op_,
		right_->clone()  // 深拷贝右子树
	);
}

double ConditionalNode::eval(const std::unordered_map<std::string, double>& vars) const {
	return cond_->eval(vars) ? true_->eval(vars) : false_->eval(vars);
}

std::unique_ptr<ASTNode> ConditionalNode::clone() const {
	return std::make_unique<ConditionalNode>(
		cond_->clone(),   // 深拷贝条件
		true_->clone(),   // 深拷贝真分支
		false_->clone()   // 深拷贝假分支
	);
}

FunctionNode::FunctionNode(std::string name, std::vector<std::unique_ptr<ASTNode>> args)
	: name_(std::move(name)), args_(std::move(args)) {}

double FunctionNode::eval(const std::unordered_map<std::string, double>& vars) const {
	if (name_ == "max") {
		if (args_.size() != 2) LOG_ERROR("max requires 2 arguments");
		return std::max(args_[0]->eval(vars), args_[1]->eval(vars));
	}
	if (name_ == "min") {
		if (args_.size() != 2) LOG_ERROR("min requires 2 arguments");
		return std::min(args_[0]->eval(vars), args_[1]->eval(vars));
	}
	if (name_ == "clamp") {
		if (args_.size() != 3) LOG_ERROR("clamp requires 3 arguments");
		double val = args_[0]->eval(vars);
		double lo = args_[1]->eval(vars);
		double hi = args_[2]->eval(vars);
		return std::clamp(val, lo, hi);
	}
	LOG_ERROR("Unknown function: %s", name_.c_str());
}

std::unique_ptr<ASTNode> FunctionNode::clone() const {
	std::vector<std::unique_ptr<ASTNode>> cloned_args;
	for (const auto& arg : args_) {
		cloned_args.push_back(arg->clone()); // 深拷贝所有参数
	}
	return std::make_unique<FunctionNode>(name_, std::move(cloned_args));
}

void Parser::advance() {
	current_ = tokenizer_.next();
}

[[noreturn]] void Parser::error(const std::string& msg) const {
	LOG_ERROR("Parse error at position %zu: %s", current_.position, msg.c_str());
}

Parser::Parser(std::string expr) : tokenizer_(std::move(expr)) {
	advance();
	if (current_.type == TokenType::End) error("Empty expression");
}

std::unique_ptr<ASTNode> Parser::parse() {
	auto expr = parseConditional();
	if (current_.type != TokenType::End) error("Unexpected tokens");
	return expr;
}

std::unique_ptr<ASTNode> Parser::parseExpression() {
	return parseConditional();
}

std::unique_ptr<ASTNode> Parser::parseConditional() {
	// 先解析基础条件（比较运算）
	auto cond = parseComparison();

	// 处理 and-or 组合
	if (current_.value == "and") {
		advance(); // 跳过 and

		// 解析 and 右侧的表达式（b部分）
		auto trueExpr = parseComparison(); // 改为调用 parseComparison() 而非递归

		// 强制检查 or
		if (current_.value != "or") {
			error("Expected 'or' after 'and' expression");
		}
		advance(); // 跳过 or

		// 解析 or 右侧的表达式（c部分）
		auto falseExpr = parseComparison();

		// 构建三目表达式节点
		return std::make_unique<ConditionalNode>(
			std::move(cond),
			std::move(trueExpr),
			std::move(falseExpr)
		);
	}

	// 单独出现 or 直接报错
	if (current_.value == "or") {
		error("Unexpected 'or' without preceding 'and'");
	}

	return cond;
}

std::unique_ptr<ASTNode> Parser::parseComparison() {
	auto node = parseAddSub();
	while (current_.type == TokenType::Operator) {
		std::string op = current_.value;
		// 检查是否为合法的比较运算符
		if (op == ">" || op == "<" || op == ">=" || op == "<=" ||
			op == "==" || op == "~=") {
			advance(); // 消费当前运算符
			auto right = parseAddSub(); // 解析右侧表达式
			node = std::make_unique<ComparisonNode>(
				std::move(node), op, std::move(right)
			);
		}
		else {
			break; // 非比较运算符则退出循环
		}
	}
	return node;
}

std::unique_ptr<ASTNode> Parser::parseAddSub() {
	auto node = parseMulDiv();
	while (current_.type == TokenType::Operator) {
		if (current_.value == "+" || current_.value == "-") {
			char op = current_.value[0];
			advance();
			node = std::make_unique<BinaryOpNode>(std::move(node), op, parseMulDiv());
		}
		else {
			break;
		}
	}
	return node;
}

std::unique_ptr<ASTNode> Parser::parseMulDiv() {
	auto node = parsePower();
	while (current_.type == TokenType::Operator) {
		if (current_.value == "*" || current_.value == "/") {
			char op = current_.value[0];
			advance();
			node = std::make_unique<BinaryOpNode>(std::move(node), op, parsePower());
		}
		else {
			break;
		}
	}
	return node;
}

std::unique_ptr<ASTNode> Parser::parsePower() {
	auto node = parsePrimary();
	while (current_.type == TokenType::Operator && current_.value == "^") {
		advance();
		node = std::make_unique<BinaryOpNode>(std::move(node), '^', parsePrimary());
	}
	return node;
}

std::unique_ptr<ASTNode> Parser::parsePrimary() {
	if (current_.type == TokenType::LeftParen) {
		advance();
		auto node = parseConditional();
		if (current_.type != TokenType::RightParen) error("Mismatched parentheses");
		advance();
		return node;
	}

	if (current_.type == TokenType::Number) {
		double value;
		try {
			value = std::stod(current_.value);
		}
		catch (...) {
			error("Invalid number format");
		}
		advance();
		return std::make_unique<NumberNode>(value);
	}

	if (current_.type == TokenType::Identifier) {
		std::string name = current_.value;
		advance();
		if (current_.type == TokenType::LeftParen) {
			return parseFunctionCall(name);
		}
		return std::make_unique<VariableNode>(std::move(name));
	}

	error("Unexpected token");
}

std::unique_ptr<ASTNode> Parser::parseFunctionCall(const std::string& name) {
	advance(); // eat '('
	std::vector<std::unique_ptr<ASTNode>> args;
	while (current_.type != TokenType::RightParen) {
		args.push_back(parseConditional());
		if (current_.type == TokenType::Comma) {
			advance();
		}
		else if (current_.type != TokenType::RightParen) {
			error("Expected comma or ) in function call");
		}
	}
	advance(); // eat ')'
	return std::make_unique<FunctionNode>(name, std::move(args));
}


struct LuaExpressionParser::Impl {
	std::unique_ptr<ASTNode> ast_;

	Impl(const std::string& expr) {
		try {
			Parser parser(expr.substr(7)); // skip "return "
			ast_ = parser.parse();
		}
		catch (...) {
			LOG_ERROR("Failed to parse expression: %s", expr.c_str());
		}
	}

	double evaluate(const std::unordered_map<std::string, double>& vars) const {
		try {
			return ast_->eval(vars);
		}
		catch (...) {
			LOG_ERROR("Evaluation error");
		}
	}
};

LuaExpressionParser::LuaExpressionParser(const std::string& expr) : impl_(new Impl(expr)) {}
LuaExpressionParser::~LuaExpressionParser() = default;
double LuaExpressionParser::evaluate(const std::unordered_map<std::string, double>& vars) const {
	return impl_->evaluate(vars);
}

VCMI_LIB_NAMESPACE_END
