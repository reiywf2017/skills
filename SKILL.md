---
name: sonarqube-java
description: >
  Java 代码生成时必须遵守的 SonarQube 质量规则集。
  任何涉及编写、生成、创建、修改、重构 Java 代码的任务都必须自动使用此技能。
  本技能覆盖安全漏洞、可靠性缺陷、可维护性问题三大维度，
  等同于 SonarQube SonarWay 推荐规则集的子集。
user-invocable: false
disable-model-invocation: false
---

<!-- ================================================================
     教学注释说明：
     1. 所有 <!-- --> 注释块是给人类阅读的教学内容，AI 会忽略它们
     2. YAML 头部（---之间的部分）是元数据：
        - name: 技能唯一标识，必须小写+连字符，必须与目录名一致
        - description: 决定 AI 何时自动加载此技能，要覆盖所有触发场景
        - user-invocable: false 表示不出现在斜杠命令菜单中
        - disable-model-invocation: false 表示允许自动加载
        这两个字段只有 GitHub Copilot 识别，Claude Code 会忽略
     3. 存放位置选择：
        - .github/skills/sonarqube-java/SKILL.md → 只有 GitHub Copilot 读取
        - .claude/skills/sonarqube-java/SKILL.md  → Copilot 和 Claude Code 都读取
        - .agents/skills/sonarqube-java/SKILL.md  → 通用标准，两者都读取
        本文件放在 .claude/skills/ 下，确保两个 AI 工具通用
     4. AI 读取此文件时，只会处理正文部分的规则指令
        所以所有规则必须写在注释之外
     ================================================================ -->

# Java 代码 SonarQube 质量规范

<!-- 教学点：正文第一段是 AI 最先读到的内容，应该用一两句话讲清楚核心要求 -->
生成任何 Java 代码时，必须同时遵守本文档中的所有规则。这些规则来源于 SonarQube SonarWay 规则集，覆盖安全、可靠性、可维护性三个维度。不允许输出任何违反以下规则的代码。

<!-- 教学点：规则按 SonarQube 的严重程度排列，安全 > 可靠性 > 可维护性
     每条规则包含：规则编号、规则名称、违规示例、合规示例
     示例代码块对 AI 的引导效果远大于纯文字描述 -->

---

## 一、安全规则

<!-- 教学点：安全规则对应 SonarQube 的 Vulnerability 和 Security Hotspot 类型
     这是最高优先级，违反会导致生产安全事故
     AI 生成代码时最容易犯的安全错误：SQL拼接、硬编码密码、不安全协议 -->

### 规则 S2077 — 禁止 SQL 拼接，必须使用参数化查询

AI 生成所有数据库操作代码时，必须使用 `PreparedStatement` 或 JPA/Hibernate 的参数绑定机制。禁止将任何变量直接拼接到 SQL 字符串中。

```java
// 违规 — SQL注入漏洞，攻击者可通过 id 参数注入恶意 SQL
String sql = "SELECT * FROM users WHERE id = " + id;
Statement stmt = conn.createStatement();
stmt.executeQuery(sql);

// 合规 — 使用 PreparedStatement 参数化查询
String sql = "SELECT * FROM users WHERE id = ?";
try (PreparedStatement stmt = conn.prepareStatement(sql)) {
    stmt.setString(1, id);
    ResultSet rs = stmt.executeQuery(sql);
}
```

对 LIKE 查询同样适用：
```java
// 违规
String sql = "SELECT * FROM users WHERE name LIKE '%" + name + "%'";

// 合规
String sql = "SELECT * FROM users WHERE name LIKE ?";
stmt.setString(1, "%" + name + "%");
```

### 规则 S2089 — 禁止硬编码凭证和敏感信息

密码、API Key、Token、Secret、数据库连接串中的凭证不允许出现在源代码中。必须从环境变量、配置文件（不在版本控制中）或密钥管理服务中获取。

```java
// 违规 — 密码明文写在代码中
private String password = "Admin@123456";
private static final String API_KEY = "sk-abc123def456";

// 合规 — 从环境变量读取
private String password = System.getenv("DB_PASSWORD");
private String apiKey = System.getenv("API_KEY");

// 合规 — 从配置服务读取
@Value("${database.password}")
private String dbPassword;
```

### 规则 S5332 — 禁止使用不安全的明文协议

不允许使用 `http://`、`ftp://`、`telnet://` 等明文协议传输数据，必须使用加密协议。

```java
// 违规
URL url = new URL("http://api.example.com/users");
RestTemplate restTemplate = new RestTemplate();
restTemplate.getForObject("http://api.example.com/data", String.class);

// 合规
URL url = new URL("https://api.example.com/users");
restTemplate.getForObject("https://api.example.com/data", String.class);
```

### 规则 S6287 — 敏感数据禁止记录到日志

密码、身份证号、银行卡号、手机号、Token 等敏感信息不允许出现在日志输出中。脱敏后方可记录。

```java
// 违规 — 密码被记录到日志
logger.info("User login: name={}, password={}", username, password);
logger.info("Phone number: " + user.getPhone());

// 合规 — 脱敏处理
logger.info("User login: name={}", username);
logger.info("Phone number: {}****{}", phone.substring(0, 3), phone.substring(7));
```

### 规则 S2755 — XML 解析必须禁用外部实体

生成 XML 解析相关代码时，必须禁用 DTD 和外部实体处理，防止 XXE 攻击。

```java
// 违规 — 默认配置允许外部实体
DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
DocumentBuilder builder = factory.newDocumentBuilder();

// 合规 — 禁用 DTD 和外部实体
DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
factory.setFeature("http://xml.org/sax/features/external-general-entities", false);
factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
DocumentBuilder builder = factory.newDocumentBuilder();
```

---

## 二、可靠性规则

<!-- 教学点：可靠性规则对应 SonarQube 的 Bug 类型
     这些是"代码逻辑上有错"的问题，可能导致运行时异常或数据错误
     AI 生成代码时最容易犯的可靠性错误：空指针、字符串比较、资源泄漏 -->

### 规则 S2259 — 所有解引用操作前必须做空指针防护

对象在调用方法、访问字段前，如果存在为 null 的可能性，必须进行检查。

```java
// 违规 — user 可能为 null，直接调用方法
public String getUserName(User user) {
    return user.getName().toUpperCase();
}

// 合规 — 使用 Optional 或 null 检查
public String getUserName(User user) {
    if (user == null || user.getName() == null) {
        return "";
    }
    return user.getName().toUpperCase();
}

// 合规 — 方法返回值推荐使用 Optional
public Optional<User> findById(String id) {
    // ...
    return Optional.ofNullable(user);
}
```

从集合中取值时同样必须防护：
```java
// 违规 — List.get() 可能返回 null，Map.get() 可能返回 null
String value = list.get(0).trim();
String config = map.get("key").toString();

// 合规
String value = Optional.ofNullable(list.get(0))
    .map(String::trim)
    .orElse("");
String config = Optional.ofNullable(map.get("key"))
    .map(Object::toString)
    .orElse("");
```

### 规则 S4973 — 字符串和包装类型必须使用 equals 比较

`String`、`Integer`、`Long` 等包装类型比较值时禁止使用 `==` 或 `!=`，必须使用 `equals()`。推荐将常量放在 `equals()` 的左侧以避免空指针。

```java
// 违规 — == 比较的是引用地址，不是值
if (status == "active") { ... }
if (user.getRole() == Role.ADMIN) { ... }
if (count == new Integer(100)) { ... }

// 合规 — 常量在左侧，避免 NPE
if ("active".equals(status)) { ... }
if (Role.ADMIN.equals(user.getRole())) { ... }
```

### 规则 S2093 — 资源必须使用 try-with-resources 关闭

`Connection`、`Statement`、`ResultSet`、`InputStream`、`OutputStream`、`Reader`、`Writer`、`Stream` 等所有实现了 `AutoCloseable` 的资源，必须使用 try-with-resources 语句，禁止手动 close()。

```java
// 违规 — 手动关闭，异常时可能泄漏
Connection conn = DriverManager.getConnection(url);
Statement stmt = conn.createStatement();
ResultSet rs = stmt.executeQuery(sql);
// 如果这里抛异常，conn 和 stmt 都不会被关闭
rs.close();
stmt.close();
conn.close();

// 违规 — 在 finally 中手动关闭，繁琐且易遗漏
Connection conn = null;
try {
    conn = DriverManager.getConnection(url);
    // ...
} finally {
    if (conn != null) { conn.close(); }
}

// 合规 — try-with-resources 自动关闭所有资源，即使发生异常
try (Connection conn = DriverManager.getConnection(url);
     PreparedStatement stmt = conn.prepareStatement(sql)) {
    stmt.setString(1, id);
    try (ResultSet rs = stmt.executeQuery()) {
        if (rs.next()) {
            // 处理结果
        }
    }
}
```

### 规则 S1181 — 禁止捕获 Throwable 或顶层 Exception

catch 块必须捕获具体的异常类型（如 `SQLException`、`IOException`），禁止捕获 `Throwable`、`Error` 或通用的 `Exception`。

```java
// 违规 — 捕获 Throwable 会吞掉 Error（如 OutOfMemoryError）
try {
    // ...
} catch (Throwable t) {
    t.printStackTrace();
}

// 违规 — 捕获通用 Exception 太宽泛
try {
    // ...
} catch (Exception e) {
    e.printStackTrace();
}

// 合规 — 捕获具体异常并妥善处理
try {
    // ...
} catch (SQLException e) {
    throw new DataAccessException("数据库操作失败", e);
} catch (IOException e) {
    throw new StorageException("文件读写失败", e);
}
```

### 规则 S108 — 禁止空的 catch 块

catch 块中不允许为空。至少需要：
- 记录日志，或
- 重新抛出包装后的异常，或
- 恢复中断状态（InterruptedException 的场景）

```java
// 违规 — 静默吞掉异常，出问题时无法排查
try {
    parseConfig();
} catch (ParseException e) {
}

// 合规 — 记录日志
try {
    parseConfig();
} catch (ParseException e) {
    logger.warn("配置解析失败，使用默认配置", e);
}

// 合规 — InterruptedException 恢复中断
try {
    Thread.sleep(1000);
} catch (InterruptedException e) {
    Thread.currentThread().interrupt();
}

// 合规 — 包装后重新抛出
try {
    parseConfig();
} catch (ParseException e) {
    throw new ConfigurationException("配置文件格式错误", e);
}
```

### 规则 S3655 — Optional 值必须先检查再获取

调用 `Optional.get()` 前必须先调用 `isPresent()` 检查，否则在值不存在时会抛 `NoSuchElementException`。推荐使用 `orElse`、`orElseThrow`、`map`、`filter` 等链式方法替代。

```java
// 违规 — Optional.get() 不检查直接取值
Optional<User> user = repository.findById(id);
return user.get().getName();

// 合规 — 使用 orElseThrow 明确语义
return repository.findById(id)
    .orElseThrow(() -> new UserNotFoundException("用户不存在, id=" + id))
    .getName();

// 合规 — 提供默认值
return repository.findById(id)
    .map(User::getName)
    .orElse("unknown");
```

### 规则 S2142 — InterruptedException 必须被妥善处理

捕获 `InterruptedException` 后，必须恢复线程的中断状态或重新抛出。不允许吞掉中断信号。

```java
// 违规 — 吞掉中断信号
try {
    queue.put(item);
} catch (InterruptedException e) {
    // 什么都没做
}

// 合规 — 恢复中断状态
try {
    queue.put(item);
} catch (InterruptedException e) {
    Thread.currentThread().interrupt();
}
```

### 规则 S3984 — 异常必须被抛出或记录

创建了异常对象但没有抛出或记录，等于没有处理错误。

```java
// 违规 — 创建了异常但没有抛出
if (value < 0) {
    new IllegalArgumentException("值不能为负数");
}

// 合规
if (value < 0) {
    throw new IllegalArgumentException("值不能为负数: " + value);
}
```

---

## 三、可维护性规则

<!-- 教学点：可维护性规则对应 SonarQube 的 Code Smell 类型
     这些问题不会导致运行时错误，但会影响代码的可读性和可维护性
     AI 生成代码时最容易犯的可维护性问题：命名不规范、方法过长、魔法数字 -->

### 规则 S2386 — 可变字段禁止声明为 public static

`public static` 的可变集合或数组可以被任何代码修改，是全局状态的隐患。必须使用不可变包装或改为 private。

```java
// 违规 — 全局可变状态
public static List<String> CACHE = new ArrayList<>();
public static Map<String, Object> CONFIG = new HashMap<>();
public static String[] NAMES = {"Alice", "Bob"};

// 合规 — 不可变 + private
private static final List<String> CACHE = List.of("key1", "key2");
private static final Map<String, Object> CONFIG = Map.of("key", "value");
public static final List<String> NAMES = Collections.unmodifiableList(
    Arrays.asList("Alice", "Bob")
);
```

### 规则 S1948 — Serializable 类的字段必须是可序列化的

如果类实现了 `Serializable` 接口，所有非 transient 字段本身也必须是可序列化的。

```java
// 违规 — Thread 不是 Serializable
public class Session implements Serializable {
    private String sessionId;
    private Thread worker;  // Thread 不可序列化
}

// 合规 — 标记为 transient 或更换类型
public class Session implements Serializable {
    private String sessionId;
    private transient Thread worker;
}
```

### 规则 S138 — 方法体不超过 30 行

单个方法的行数（不含签名和空行）不超过 30 行。如果逻辑复杂必须拆分为多个私有方法，每个方法只做一件事。

```java
// 违规 — 80行的巨型方法
public OrderResult processOrder(OrderRequest request) {
    // 验证参数... 20行
    // 查库存... 15行
    // 算价格... 20行
    // 创建订单... 15行
    // 发通知... 10行
}

// 合规 — 拆分为多个方法，主方法作为流程编排
public OrderResult processOrder(OrderRequest request) {
    validateRequest(request);
    checkInventory(request.getItems());
    BigDecimal totalPrice = calculatePrice(request);
    Order order = createOrder(request, totalPrice);
    sendNotification(order);
    return OrderResult.success(order.getId());
}
```

### 规则 S107 — 方法参数不超过 5 个

方法参数超过 5 个时，可读性急剧下降。必须将相关参数封装为对象（Request DTO 或 Parameter Object）。

```java
// 违规 — 7个参数
public void createUser(String name, String email, String phone,
                       String role, String department, String avatar,
                       String manager) { ... }

// 合规 — 封装为请求对象
public void createUser(CreateUserRequest request) { ... }

public class CreateUserRequest {
    private String name;
    private String email;
    private String phone;
    private String role;
    private String department;
    // getter/setter/builder
}
```

### 规则 S109 — 魔法数字必须定义为命名常量

代码中出现的数字字面量（0、1 除外）必须提取为 `static final` 常量，常量名要能表达含义。

```java
// 违规 — 数字含义不明
if (status == 3) { ... }
Thread.sleep(5000);
if (retryCount > 5) { ... }

// 合规 — 常量名即文档
private static final int STATUS_SUSPENDED = 3;
private static final long RETRY_DELAY_MS = 5000L;
private static final int MAX_RETRY_COUNT = 5;

if (status == STATUS_SUSPENDED) { ... }
Thread.sleep(RETRY_DELAY_MS);
if (retryCount > MAX_RETRY_COUNT) { ... }
```

### 规则 S121 — 控制语句必须使用大括号

`if`、`else`、`for`、`while`、`do` 语句体必须用大括号包裹，即使只有一行代码。

```java
// 违规 — 省略大括号容易在后续修改时引入 bug
if (isValid)
    process();

// 合规
if (isValid) {
    process();
}
```

### 规则 S131 — switch 语句必须包含 default 分支

`switch` 语句必须有 `default` 分支，即使是空实现也应显式写出，表明开发者考虑了其他情况。

```java
// 违规 — 没有 default
switch (status) {
    case "ACTIVE":
        return 1;
    case "INACTIVE":
        return 0;
}

// 合规
switch (status) {
    case "ACTIVE":
        return 1;
    case "INACTIVE":
        return 0;
    default:
        logger.warn("未知状态: {}", status);
        return -1;
}
```

### 规则 S1068 — 禁止存在未使用的成员

未使用的字段、方法、局部变量、import 语句必须删除。

```java
// 违规
import java.util.Date;        // 未使用
private String remark;          // 未使用
private void oldMethod() { }    // 未使用
int temp = calculate();         // temp 未被后续使用

// 合规 — 删除所有未使用的元素
```

### 规则 S1118 — 工具类必须私有化构造器

只包含静态方法的工具类（Utility Class）必须有 `private` 构造器，防止被意外实例化。

```java
// 违规 — 可以被 new StringUtils()
public class StringUtils {
    public static boolean isEmpty(String s) { ... }
}

// 合规 — 私有构造器
public class StringUtils {
    private StringUtils() {
        throw new UnsupportedOperationException("工具类不允许实例化");
    }
    public static boolean isEmpty(String s) { ... }
}
```

### 规则 S115 — 常量命名使用 UPPER_SNAKE_CASE

`static final` 字段的命名必须全部大写，单词间用下划线分隔。

```java
// 违规
private static final int maxRetryCount = 3;
private static final String DbUrl = "jdbc:mysql://...";

// 合规
private static final int MAX_RETRY_COUNT = 3;
private static final String DB_URL = "jdbc:mysql://...";
```

### 规则 S116 — 字段命名使用 camelCase

非常量的字段命名必须使用驼峰命名法，首字母小写。

```java
// 违规
private String User_Name;
private int phone_number;

// 合规
private String userName;
private int phoneNumber;
```

### 规则 S117 — 局部变量命名使用 camelCase

局部变量和方法参数的命名必须使用驼峰命名法，首字母小写。

```java
// 违规
String User_Name = request.getName();
int Total_Count = list.size();

// 合规
String userName = request.getName();
int totalCount = list.size();
```

---

## 四、异常处理专项规则

<!-- 教学点：异常处理是 AI 生成代码的重灾区
     AI 倾向于：捕获 Exception 然后 printStackTrace、空的 catch 块、丢失异常上下文
     这个专项模块集中规范异常处理模式 -->

### 规则 S112 — 禁止直接抛出 Exception 或 RuntimeException

方法签名中不允许声明抛出 `Exception`、`RuntimeException`、`Throwable`，必须定义或使用具体的异常类型。

```java
// 违规
public User findUser(String id) throws Exception { ... }
public void process() throws RuntimeException { ... }

// 合规
public User findUser(String id) throws UserNotFoundException { ... }
public void process() throws ProcessingException { ... }
```

### 规则 S1130 — 异常的 catch 块不能是 U 型继承

如果 catch 块同时捕获父类和子类异常，且父类在后面，则父类的 catch 永远不会被执行到。

```java
// 违规 — IOException 已被第一个 catch 处理，第二个 catch 永远不执行
try {
    // ...
} catch (IOException e) {
    // ...
} catch (Exception e) {  // 永远不会捕获 IOException
    // ...
}

// 合规 — 调整顺序或合并处理
try {
    // ...
} catch (FileNotFoundException e) {
    // 处理文件不存在
} catch (IOException e) {
    // 处理其他 IO 异常
}
```

### 规则 S1165 — 异常信息不能为空

抛出异常时必须提供描述信息，不允许使用无参构造器。

```java
// 违规
throw new NullPointerException();
throw new IllegalArgumentException();

// 合规
throw new NullPointerException("用户对象不能为空, userId=" + userId);
throw new IllegalArgumentException("年龄必须在 0-150 之间, 实际值: " + age);
```

### 规则 S5164 — 日志参数数量必须与占位符匹配

使用 SLF4J/Log4j 等日志框架时，参数数量必须与 `{}` 占位符数量一致。

```java
// 违规 — 2个占位符，3个参数
logger.info("User {} login from {}", userId, ip, extra);

// 违规 — 1个占位符，0个参数
logger.error("Processing failed for userId={}");


// 合规
logger.info("User {} login from {}", userId, ip);
logger.error("Processing failed for userId={}", userId);
```

---

## 五、编码风格强制规则

<!-- 教学点：风格规则看起来"低级"，但团队协作中价值很大
     AI 通常已经有不错的命名习惯，这里主要是确保一致性 -->

### 规则 S1182 — 类名使用 PascalCase

```java
// 违规
public class user_service { }
public class UserServiceImpl2 extends BaseService { }

// 合规
public class UserService { }
public class DefaultUserService extends BaseService { }
```

### 规则 S1144 — 未使用的 private 方法必须删除

```java
// 违规
private void sortByName(List<User> users) {
    // 这个方法没有被调用
}

// 合规 — 直接删除，版本控制系统会保留历史
```

### 规则 S1481 — 未使用的局部变量必须删除

```java
// 违规
public void process() {
    String temp = calculate();  // temp 从未被使用
    int count = items.size();   // count 从未被使用
    execute();
}

// 合规
public void process() {
    execute();
}
```

---

## 六、生成后自检清单

<!-- 教学点：自检清单的作用是强制 AI 在输出前再做一次检查
     虽然和上面的规则有重复，但"清单式检查"对 LLM 的引导效果比"规则式描述"更强
     这里的每一条对应上面一个高频违规点 -->

在输出最终代码之前，逐项确认以下检查。如果任何一项不通过，必须在输出前自行修正：

1. **凭证检查**：代码中是否包含硬编码的密码、密钥、Token？
2. **SQL 检查**：是否存在变量直接拼接 SQL 字符串？
3. **空指针检查**：是否存在可能为 null 的对象直接调用方法？
4. **字符串比较检查**：是否存在使用 `==` 比较字符串或包装类型？
5. **资源关闭检查**：所有 AutoCloseable 资源是否使用了 try-with-resources？
6. **空 catch 检查**：是否存在空的 catch 块？
7. **异常类型检查**：是否捕获了 Throwable、Error 或通用 Exception？
8. **字段可见性检查**：是否存在 public static 的可变集合或数组？
9. **方法长度检查**：是否有方法体超过 30 行？
10. **参数数量检查**：是否有方法参数超过 5 个？
11. **未使用成员检查**：是否存在未使用的字段、方法、变量、import？
12. **命名规范检查**：常量是否 UPPER_SNAKE_CASE，字段和方法是否 camelCase，类名是否 PascalCase？
13. **魔法数字检查**：是否存在未定义为常量的数字字面量（0、1、-1 除外）？
14. **大括号检查**：所有 if/else/for/while 是否都使用了大括号？
15. **Optional 检查**：Optional.get() 前是否有 isPresent() 或使用了 orElse/orElseThrow？

<!-- 教学点：文件到此结束。
     实际使用中，你可以根据团队反馈持续调整这份文件：
     - 如果发现某条规则从未被违反过 → 可以删除，节省上下文空间
     - 如果发现新的高频违规 → 添加对应的规则和示例
     - 如果 Copilot 生成的代码中某个问题反复出现 → 把对应规则的自检项提到更前面的位置
     这份 Skill 是一个活文档，需要根据实际使用效果迭代优化 -->
