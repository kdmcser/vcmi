/*
 * LuaExpressionParser.h, part of VCMI engine
 *
 * Authors: listed in file AUTHORS in main folder
 *
 * License: GNU General Public License v2.0 or later
 * Full text of license available in license.txt file, in main folder
 *
 */
#pragma once

#include <string>
#include <map>
#include <memory>
#include <vector>
#include <cmath>
#include <cassert>

VCMI_LIB_NAMESPACE_BEGIN


enum class TokenType {
	Number, Identifier, Operator, LeftParen, RightParen, Comma, End
};

struct Token {
	TokenType type;
	std::string value;
	size_t position;
};

class Tokenizer {
	std::string expr_;
	size_t pos_ = 0;

	char peek() const;
	void advance();
	void skipWhitespace();

public:
	Tokenizer(std::string expr);
	Token next(); 
};

class ASTNode {
public:
	virtual ~ASTNode() = default;
	virtual double eval(const std::unordered_map<std::string, double>& vars) const = 0;
	virtual std::unique_ptr<ASTNode> clone() const = 0;
};

class NumberNode : public ASTNode {
	double value_;
public:
	NumberNode(double value);
	double eval(const std::unordered_map<std::string, double>&) const override;
	std::unique_ptr<ASTNode> clone() const override;
};

class VariableNode : public ASTNode {
	std::string name_;
public:
	VariableNode(std::string name);
	double eval(const std::unordered_map<std::string, double>& vars) const override;
	std::unique_ptr<ASTNode> clone() const override;
};

class BinaryOpNode : public ASTNode {
	std::unique_ptr<ASTNode> left_, right_;
	char op_;
public:
	BinaryOpNode(std::unique_ptr<ASTNode> left, char op, std::unique_ptr<ASTNode> right);
	double eval(const std::unordered_map<std::string, double>& vars) const override;
	std::unique_ptr<ASTNode> clone() const override;
};

class ComparisonNode : public ASTNode {
	std::unique_ptr<ASTNode> left_, right_;
	std::string op_;
	std::unique_ptr<ASTNode> clone() const override;
public:
	ComparisonNode(std::unique_ptr<ASTNode> left, std::string op, std::unique_ptr<ASTNode> right);
	double eval(const std::unordered_map<std::string, double>& vars) const override;
};

class ConditionalNode : public ASTNode {
	std::unique_ptr<ASTNode> cond_, true_, false_;

public:
	ConditionalNode(
		std::unique_ptr<ASTNode> cond,
		std::unique_ptr<ASTNode> trueExpr,
		std::unique_ptr<ASTNode> falseExpr
	);
	static std::unique_ptr<ConditionalNode> create(
		std::unique_ptr<ASTNode> cond,
		std::unique_ptr<ASTNode> trueExpr,
		std::unique_ptr<ASTNode> falseExpr
	);
	double eval(const std::unordered_map<std::string, double>& vars) const override;
	std::unique_ptr<ASTNode> clone() const override;
};

class FunctionNode : public ASTNode {
	std::string name_;
	std::vector<std::unique_ptr<ASTNode>> args_;
public:
	FunctionNode(std::string name, std::vector<std::unique_ptr<ASTNode>> args);
	double eval(const std::unordered_map<std::string, double>& vars) const override;
	std::unique_ptr<ASTNode> clone() const override;
};

class Parser {
	Tokenizer tokenizer_;
	Token current_;

	void advance();

	[[noreturn]] void error(const std::string& msg) const;

	std::unique_ptr<ASTNode> parseExpression();
	std::unique_ptr<ASTNode> parseConditional();
	std::unique_ptr<ASTNode> parseComparison();
	std::unique_ptr<ASTNode> parseAddSub();
	std::unique_ptr<ASTNode> parseMulDiv();
	std::unique_ptr<ASTNode> parsePower();
	std::unique_ptr<ASTNode> parsePrimary();
	std::unique_ptr<ASTNode> parseFunctionCall(const std::string& name);

public:
	Parser(std::string expr);
	std::unique_ptr<ASTNode> parse();
};

class LuaExpressionParser {
public:
	LuaExpressionParser(const std::string& expr);
	~LuaExpressionParser();

	double evaluate(const std::unordered_map<std::string, double>& variables) const;

	LuaExpressionParser(const LuaExpressionParser&) = delete;
	LuaExpressionParser& operator=(const LuaExpressionParser&) = delete;

	struct Impl;
	std::unique_ptr<Impl> impl_;
};
VCMI_LIB_NAMESPACE_END
