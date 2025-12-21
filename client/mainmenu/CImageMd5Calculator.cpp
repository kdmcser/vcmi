#include"CImageMd5Calculator.h"
#include "../lib/filesystem/Filesystem.h"
#include "../lib/json/JsonUtils.h"

// MD5 algorithm constants (integer part of sine function)
static const uint32_t T[64] = {
    0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee,
    0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
    0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
    0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
    0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa,
    0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
    0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
    0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
    0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c,
    0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
    0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05,
    0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
    0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039,
    0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
    0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
    0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391
};

// Rotate left shift amounts
static const uint32_t S[64] = {
    7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
    5,  9, 14, 20, 5,  9, 14, 20, 5,  9, 14, 20, 5,  9, 14, 20,
    4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
    6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21
};

// Main function: calculate MD5
std::string CImageMd5Calculator::calculateMd5(ui8* data, si64 size)
{
    if (!data || size <= 0) {
        return "";
    }

    MD5Context context;
    ui8 digest[16];

    // Initialize MD5 context
    init(&context);

    // Update with input data
    update(&context, data, static_cast<uint32_t>(size));

    // Get final result
    final(digest, &context);

    // Convert 16-byte digest to 32-character hex string
    std::stringstream ss;
    ss << std::hex << std::setfill('0');

    for (int i = 0; i < 16; i++) {
        ss << std::setw(2) << static_cast<int>(digest[i]);
    }

    return ss.str();
}

// Initialize MD5 context
void CImageMd5Calculator::init(MD5Context* context)
{
    context->count[0] = context->count[1] = 0;

    // Load magic initialization constants
    context->state[0] = 0x67452301;
    context->state[1] = 0xefcdab89;
    context->state[2] = 0x98badcfe;
    context->state[3] = 0x10325476;
}

// Add input data to MD5 computation
void CImageMd5Calculator::update(MD5Context* context, const ui8* input, uint32_t inputLen)
{
    uint32_t i;
    uint32_t index, partLen;

    // Compute number of bytes currently in buffer
    index = (uint32_t)((context->count[0] >> 3) & 0x3F);

    // Update bit count
    context->count[0] += (inputLen << 3);
    if (context->count[0] < (inputLen << 3)) {
        context->count[1]++;
    }
    context->count[1] += (inputLen >> 29);

    partLen = 64 - index;

    // If buffer can hold all input data
    if (inputLen >= partLen) {
        std::memcpy(&context->buffer[index], input, partLen);
        transform(context->state, context->buffer);

        // Process remaining data blocks
        for (i = partLen; i + 63 < inputLen; i += 64) {
            transform(context->state, &input[i]);
        }

        index = 0;
    }
    else {
        i = 0;
    }

    // Store remaining data in buffer
    std::memcpy(&context->buffer[index], &input[i], inputLen - i);
}

// Complete MD5 computation, output digest
void CImageMd5Calculator::final(ui8 digest[16], MD5Context* context)
{
    ui8 bits[8];
    uint32_t index, padLen;

    // Save number of bits
    encode(bits, context->count, 8);

    // Pad to 448 bits (mod 512)
    index = (uint32_t)((context->count[0] >> 3) & 0x3f);
    padLen = (index < 56) ? (56 - index) : (120 - index);
    update(context, (ui8*)"\x80", 1);

    while (padLen > 1) {
        update(context, (ui8*)"\x00", 1);
        padLen--;
    }

    // Append bit length (original message length, little-endian)
    update(context, bits, 8);

    // Store state to digest
    encode(digest, context->state, 16);

    // Clear sensitive data
    std::memset(context, 0, sizeof(*context));
}

// MD5 core transformation function
void CImageMd5Calculator::transform(uint32_t state[4], const ui8 block[64])
{
    uint32_t a = state[0];
    uint32_t b = state[1];
    uint32_t c = state[2];
    uint32_t d = state[3];
    uint32_t x[16];

    // Decode input block into 16 32-bit words
    decode(x, block, 64);

    // Round 1
    for (uint32_t i = 0; i < 16; i++) {
        FF(a, b, c, d, x[i], S[i], T[i]);
        uint32_t temp = d;
        d = c;
        c = b;
        b = a;
        a = temp;
    }

    // Round 2
    for (uint32_t i = 16; i < 32; i++) {
        GG(a, b, c, d, x[(5 * i + 1) % 16], S[i], T[i]);
        uint32_t temp = d;
        d = c;
        c = b;
        b = a;
        a = temp;
    }

    // Round 3
    for (uint32_t i = 32; i < 48; i++) {
        HH(a, b, c, d, x[(3 * i + 5) % 16], S[i], T[i]);
        uint32_t temp = d;
        d = c;
        c = b;
        b = a;
        a = temp;
    }

    // Round 4
    for (uint32_t i = 48; i < 64; i++) {
        II(a, b, c, d, x[(7 * i) % 16], S[i], T[i]);
        uint32_t temp = d;
        d = c;
        c = b;
        b = a;
        a = temp;
    }

    // Update state
    state[0] += a;
    state[1] += b;
    state[2] += c;
    state[3] += d;

    // Clear temporary variables
    std::memset(x, 0, sizeof(x));
}

// Encode 32-bit integers to bytes (little-endian)
void CImageMd5Calculator::encode(ui8* output, const uint32_t* input, uint32_t len)
{
    for (uint32_t i = 0, j = 0; j < len; i++, j += 4) {
        output[j] = (ui8)(input[i] & 0xff);
        output[j + 1] = (ui8)((input[i] >> 8) & 0xff);
        output[j + 2] = (ui8)((input[i] >> 16) & 0xff);
        output[j + 3] = (ui8)((input[i] >> 24) & 0xff);
    }
}

// Decode bytes to 32-bit integers (little-endian)
void CImageMd5Calculator::decode(uint32_t* output, const ui8* input, uint32_t len)
{
    for (uint32_t i = 0, j = 0; j < len; i++, j += 4) {
        output[i] = ((uint32_t)input[j]) |
            (((uint32_t)input[j + 1]) << 8) |
            (((uint32_t)input[j + 2]) << 16) |
            (((uint32_t)input[j + 3]) << 24);
    }
}

ImagePath CImageMd5Calculator::getRealImagePath(const ImagePath& imagePath)
{
	int validCount = 0;
	ImagePath retPath = imagePath;
	std::vector<ImagePath> possiablePaths = {imagePath, imagePath.addPrefix("DATA/"), imagePath.addPrefix("SPRITES/")};

	for (auto& path : possiablePaths)
	{
		if (CResourceHandler::get()->existsResource(path))
		{
			retPath = path;
			validCount++;
		}
	}
	if(validCount > 1)
	{
		logGlobal->error("Get real image path %s conflict in DATA, SPIRTES and root.", imagePath.getOriginalName());
		return ImagePath();
	}
	return retPath;
}

std::string CImageMd5Calculator::calculate(const ImagePath& imagePath)
{
	ImagePath realPath = getRealImagePath(imagePath);
	if (!CResourceHandler::get()->existsResource(realPath))
	{
		logGlobal->error("Fail to find image oath %s", imagePath.getOriginalName());
		return "";
	}
	auto readFile = CResourceHandler::get()->load(realPath)->readAll();
	return calculateMd5(readFile.first.get(), readFile.second);
}

std::string CImageMd5Calculator::calculate(const AnimationPath & animationPath)
{
	AnimationPath actualPath = boost::starts_with(animationPath.getName(), "SPRITES") ? animationPath : animationPath.addPrefix("SPRITES/");
	bool existDef = CResourceHandler::get()->existsResource(actualPath);
	auto jsonResource = actualPath.toType<EResType::JSON>();
	auto configList = CResourceHandler::get()->getResourcesWithName(jsonResource);
	bool existJson = configList.size() > 0;
	if(existDef && existJson)
	{
		logGlobal->error("Def and json are all existed in %s!", animationPath.getOriginalName());
		return "";
	}

	if (existDef)
	{
		auto readFile = CResourceHandler::get()->load(actualPath)->readAll();
		return calculateMd5(readFile.first.get(), readFile.second);
	}

	if(existJson)
	{
		auto stream = configList[0]->load(jsonResource);
		std::unique_ptr<ui8[]> textData(new ui8[stream->getSize()]);
		stream->read(textData.get(), stream->getSize());
		const JsonNode config(reinterpret_cast<const std::byte *>(textData.get()), stream->getSize(), actualPath.getOriginalName());
		auto blocks = readDefJsonImages(config);
		if(blocks.empty())
			return "";

		size_t totalSize = stream->getSize();
		for(auto & block : blocks)
			totalSize += static_cast<size_t>(block.second);

		std::unique_ptr<ui8[]> merged = std::make_unique<ui8[]>(totalSize);
		std::memcpy(merged.get(), textData.get(), stream->getSize());
		size_t offset = stream->getSize();
		for(size_t i = 0; i < blocks.size(); i++)
		{
			size_t blockSize = static_cast<size_t>(blocks[i].second);
			if(offset + blockSize > totalSize)
				throw std::runtime_error("Copy unexpected data!");
			std::memcpy(merged.get() + offset, blocks[i].first.get(), blockSize);
			offset += blockSize;
		}
		return calculateMd5(merged.get(), totalSize);
	}
	logGlobal->error("Neither def or json are existed in %s!", animationPath.getOriginalName());
	return "";
}

std::vector<std::pair<std::unique_ptr<ui8[]>, si64> > CImageMd5Calculator::readDefJsonImages(const JsonNode & config)
{
	std::vector<std::pair<std::unique_ptr<ui8[]>, si64> > ret;
	std::vector<std::pair<std::unique_ptr<ui8[]>, si64> > emptyRet;
	std::string basepath = config["basepath"].String();
	for (const JsonNode& group : config["sequences"].Vector())
	{
		for (const JsonNode& frame : group["frames"].Vector())
		{
			ImagePath imagePath = ImagePath::builtin(basepath + frame.String());
			auto imageData = readOneImage(imagePath);
			if(imageData.first.get() == nullptr)
				return emptyRet;
			ret.emplace_back(std::move(imageData.first), imageData.second);
		}
	}
	for (const JsonNode& node : config["images"].Vector())
	{
		if (!node["defFile"].isNull())
		{
			logGlobal->error("Not support setting defFile!");
			return emptyRet;
		}

		ImagePath imagePath = ImagePath::builtin(basepath + node["file"].String());
		auto imageData = readOneImage(imagePath);
		if(imageData.first.get() == nullptr)
			return emptyRet;
		ret.emplace_back(std::move(imageData.first), imageData.second);
	}
	return ret;
}

std::pair<std::unique_ptr<ui8[]>, si64> CImageMd5Calculator::readOneImage(const ImagePath &imagePath)
{
	static constexpr std::array unexceptedPaths = {"SPRITES2X/", "SPRITES3X/", "SPRITES4X/"};
	for(auto & path : unexceptedPaths)
	{
		if(CResourceHandler::get()->existsResource(imagePath.addPrefix(path)))
		{
			logGlobal->error("Not support scaled image oath %s", imagePath.addPrefix(path).getOriginalName());
			return std::make_pair<std::unique_ptr<ui8[]>, si64>(nullptr, 0);
		}
	}
	ImagePath realPath = getRealImagePath(imagePath);
	if(!CResourceHandler::get()->existsResource(realPath))
	{
		logGlobal->error("Fail to find image oath %s", imagePath.getOriginalName());
		return std::make_pair<std::unique_ptr<ui8[]>, si64>(nullptr, 0);
	}
	return CResourceHandler::get()->load(realPath)->readAll();
}
